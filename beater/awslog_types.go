package beater

import (
	"fmt"
	"strings"
)

// data struct matching the defined fields of a CloudTrail Record as
//  described in:
//  http://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
type cloudtrailLog struct {
	Records []cloudtrailEvent
}
type cloudtrailEvent struct {
	EventTime			string					`json:"eventTime"`
	EventVersion		string					`json:"eventVersion"`
	EventSource			string					`json:"eventSource"`
	UserIdentity		map[string]interface{}	`json:"userIdentity"`
	EventName			string					`json:"eventName"`
	AwsRegion			string					`json:"awsRegion"`
	SourceIPAddress		string					`json:"sourceIPAddress"`
	UserAgent			string					`json:"userAgent"`
	ErrorCode			string					`json:"errorCode"`
	ErrorMessage		string					`json:"errorMessage,omitempty"`
	RequestParameters	map[string]interface{}	`json:"requestParameters"`
	RequestID			string					`json:"requestID"`
	EventID				string					`json:"eventID"`
	EventType			string					`json:"eventType"`
	APIVersion			string					`json:"apiVersion"`
	RecipientAccountID	string					`json:"recipientAccountID"`
}


type clouttrailEventFieldFunction func(e *cloudtrailEvent) interface{}

var cloudtrailEventField = map[string]clouttrailEventFieldFunction{
    "EventTime": func(t *cloudtrailEvent) interface{}          { return t.EventTime },
    "EventVersion": func(t *cloudtrailEvent) interface{}       { return t.EventVersion },
    "EventSource": func(t *cloudtrailEvent) interface{}        { return t.EventSource },
    "UserIdentity": func(t *cloudtrailEvent) interface{}       { return t.UserIdentity },
    "EventName": func(t *cloudtrailEvent) interface{}          { return t.EventName },
    "AwsRegion": func(t *cloudtrailEvent) interface{}          { return t.AwsRegion },
    "SourceIPAddress": func(t *cloudtrailEvent) interface{}    { return t.SourceIPAddress },
    "UserAgent": func(t *cloudtrailEvent) interface{}          { return t.UserAgent },
    "ErrorCode": func(t *cloudtrailEvent) interface{}          { return t.ErrorCode },
    "ErrorMessage": func(t *cloudtrailEvent) interface{}       { return t.ErrorMessage },
    "RequestParameters": func(t *cloudtrailEvent) interface{}  { return t.RequestParameters },
    "RequestID": func(t *cloudtrailEvent) interface{}          { return t.RequestID },
    "EventID": func(t *cloudtrailEvent) interface{}            { return t.EventID },
    "EventType": func(t *cloudtrailEvent) interface{}          { return t.EventType },
    "APIVersion": func(t *cloudtrailEvent) interface{}         { return t.APIVersion },
    "RecipientAccountID": func(t *cloudtrailEvent) interface{} { return t.RecipientAccountID },
}

func cloudtrailMatchPattern(event cloudtrailEvent, field string, search string) bool {
	if strings.Contains(field, "RequestParameters.") {
		parts := strings.SplitN(field, ".", 2)
		fmt.Printf("need to find %s in event.%s[\"%s\"]\n", search, parts[0], parts[1])
		searchField := cloudtrailEventField[parts[0]](&event).(map[string]interface{})[parts[1]].(string)
		fmt.Printf("field contents is: .%s\n", searchField)
		return strings.Contains(searchField, search)
	} else {
		fmt.Printf("need to find %s in event.%s\n", search, field)
		searchField := cloudtrailEventField[field](&event).(string)
		return strings.Contains(searchField, search)
	}
	return false
}
