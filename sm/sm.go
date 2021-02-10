package sm

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

const format = "%v\t%v\t\n"

type Config struct {
	sess   *session.Session
	region *string
}

func NewConfig(region string) (c Config) {
	c.region = &region
	c.sess = session.Must(session.NewSession(&aws.Config{
		Region: c.region,
	}))
	return c
}

func CreateAWSSession(region string) (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (c Config) GetSecretValue(s string, raw bool) (map[string]interface{}, error) {
	svc := secretsmanager.New(c.sess)
	input := &secretsmanager.GetSecretValueInput{
		SecretId: &s,
	}
	secretV, err := svc.GetSecretValue(input)
	if err != nil {
		return nil, err
	}

	if raw {
		fmt.Println(*secretV.SecretString)
		return nil, nil
	}

	var secretMap map[string]interface{}
	json.Unmarshal([]byte(*secretV.SecretString), &secretMap)
	return secretMap, nil

}

func PrintSecretValue(secretMap map[string]interface{}) {
	for k, v := range secretMap {
		fmt.Printf("%s: %v\n", k, v)
	}

}

func (c Config) ListSecrets(nextToken *string, maxResults int64) ([]*secretsmanager.SecretListEntry, *string, error) {
	svc := secretsmanager.New(c.sess)
	input := &secretsmanager.ListSecretsInput{
		MaxResults: &maxResults,
		NextToken:  nextToken,
	}

	result, err := svc.ListSecrets(input)
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case secretsmanager.ErrCodeInvalidParameterException:
				fmt.Println(secretsmanager.ErrCodeInvalidParameterException, aerr.Error())
			case secretsmanager.ErrCodeInvalidNextTokenException:
				fmt.Println(secretsmanager.ErrCodeInvalidNextTokenException, aerr.Error())
			case secretsmanager.ErrCodeInternalServiceError:
				fmt.Println(secretsmanager.ErrCodeInternalServiceError, aerr.Error())
			default:
				fmt.Println(aerr.Error())
			}
		} else {
			// Print the error, cast err to awserr.Error to get the Code and
			// Message from an error.
			fmt.Printf("Unknown error: %v\n", err.Error())
		}
		return nil, nil, err
	}
	return result.SecretList, result.NextToken, nil
}

func (c Config) ListSecretsForComplete() ([]string, error) {
	var maxResults int64 = 100
	var nextToken *string
	result, nextToken, err := c.ListSecrets(nextToken, maxResults)
	if err != nil {
		return nil, err
	}
	for nextToken != nil {
		secrets, nt, err := c.ListSecrets(nextToken, maxResults)
		if err != nil {
			return nil, err
		}
		nextToken = nt
		result = append(result, secrets...)
	}
	var secretNames []string
	for _, s := range result {
		name := *s.Name
		secretNames = append(secretNames, name)
	}
	return secretNames, nil
}

func PrintSecretList(secrets []*secretsmanager.SecretListEntry, debug bool, sorted bool) {
	if debug {
		fmt.Printf("Printing %d secrets\n", len(secrets))
		fmt.Printf("Format: %s\n", format)
	}
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, format, "Name", "ARN")
	if sorted {
		sort.Sort(secretsByName(secrets))
	}
	for _, s := range secrets {
		fmt.Fprintf(tw, format, *s.Name, *s.ARN)
	}
	tw.Flush()
}

// sorting by name
type secretsByName []*secretsmanager.SecretListEntry

func (s secretsByName) Len() int {
	return len(s)
}
func (s secretsByName) Less(i, j int) bool {
	one := *s[i].Name
	two := *s[j].Name
	return one < two
}
func (s secretsByName) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func UpdateSecretValue(c Config, s string, add map[string]string, remove []string) (map[string]interface{}, error) {
	secret, err := c.GetSecretValue(s, false)
	if err != nil {
		return nil, err
	}

	for k, v := range add {
		if _, ok := secret[k]; !ok {
			fmt.Printf("Key %s doesn't exist, adding it\n", k)
		}
		secret[k] = v

	}
	for _, d := range remove {
		if _, ok := secret[d]; ok {
			delete(secret, d)
		} else {
			return nil, fmt.Errorf("Key %s doesn't exist, can't be deleted", d)
		}
	}
	return secret, nil
}

func PutSecretValue(c Config, s string, secretMap map[string]interface{}) error {
	secretByte, err := json.Marshal(secretMap)
	if err != nil {
		return fmt.Errorf("Error marshalling secret: %v", err)
	}
	svc := secretsmanager.New(c.sess)

	secretString := string(secretByte)
	input := &secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(s),
		SecretString: aws.String(secretString),
	}

	out, err := svc.PutSecretValue(input)
	if err != nil {
		return fmt.Errorf("Puting secret %s error: %v", s, err)
	}
	fmt.Printf("%s output: %s", s, out.String())
	return nil
}

func ListSecretKeys(c Config, s string) (keysL []string) {
	secret, _ := c.GetSecretValue(s, false)
	for k := range secret {
		keysL = append(keysL, k)
	}
	return keysL
}

func CompareSecrets(a, b map[string]interface{}) map[string]string {
	diff := make(map[string]string)
	am := convertMap(a)
	bm := convertMap(b)
	for k, v := range a {
		if v != b[k] {
			diff[fmt.Sprintf("%s=%s", k, am[k])] = fmt.Sprintf("%s=%s", k, bm[k])
		}
	}
	return diff
}

func convertMap(a map[string]interface{}) map[string]string {
	b := make(map[string]string)
	for k, v := range a {
		b[k] = v.(string)
	}
	return b
}

func PrintDiff(s1, s2 string, diff map[string]string) {
	fmt.Println(strings.Repeat("*", 100))
	tw := new(tabwriter.Writer).Init(os.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, format, s1, s2)

	for k, v := range diff {
		fmt.Fprintf(tw, format, k, v)
	}
	tw.Flush()
	fmt.Println(strings.Repeat("-", 100))
}
