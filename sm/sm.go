package sm

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

const format = "%v\t%v\t\n"

func CreateAWSSession(region string) (*session.Session, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func GetSecretValue(sess *session.Session, s string, raw bool) (map[string]interface{}, error) {
	svc := secretsmanager.New(sess)
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
	for k, v := range secretMap {
		fmt.Printf("%s: %v\n", k, v)
	}
	return secretMap, nil

}

func ListSecrets(sess *session.Session, nextToken *string, maxResults int64) ([]*secretsmanager.SecretListEntry, *string, error) {
	svc := secretsmanager.New(sess)
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

func ListSecretsForComplete(sess *session.Session) ([]string, error) {
	var maxResults int64 = 100
	var nextToken *string
	result, nextToken, err := ListSecrets(sess, nextToken, maxResults)
	if err != nil {
		return nil, err
	}
	for nextToken != nil {
		secrets, nt, err := ListSecrets(sess, nextToken, maxResults)
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
