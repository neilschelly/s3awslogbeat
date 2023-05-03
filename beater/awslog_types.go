package beater

import (
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


type cloudtrailEventFieldFunction func(e *cloudtrailEvent) interface{}

var cloudtrailEventField = map[string]cloudtrailEventFieldFunction{
    "EventTime": func(e *cloudtrailEvent) interface{}          { return e.EventTime },
    "EventVersion": func(e *cloudtrailEvent) interface{}       { return e.EventVersion },
    "EventSource": func(e *cloudtrailEvent) interface{}        { return e.EventSource },
    "UserIdentity": func(e *cloudtrailEvent) interface{}       { return e.UserIdentity },
    "EventName": func(e *cloudtrailEvent) interface{}          { return e.EventName },
    "AwsRegion": func(e *cloudtrailEvent) interface{}          { return e.AwsRegion },
    "SourceIPAddress": func(e *cloudtrailEvent) interface{}    { return e.SourceIPAddress },
    "UserAgent": func(e *cloudtrailEvent) interface{}          { return e.UserAgent },
    "ErrorCode": func(e *cloudtrailEvent) interface{}          { return e.ErrorCode },
    "ErrorMessage": func(e *cloudtrailEvent) interface{}       { return e.ErrorMessage },
    "RequestParameters": func(e *cloudtrailEvent) interface{}  { return e.RequestParameters },
    "RequestID": func(e *cloudtrailEvent) interface{}          { return e.RequestID },
    "EventID": func(e *cloudtrailEvent) interface{}            { return e.EventID },
    "EventType": func(e *cloudtrailEvent) interface{}          { return e.EventType },
    "APIVersion": func(e *cloudtrailEvent) interface{}         { return e.APIVersion },
    "RecipientAccountID": func(e *cloudtrailEvent) interface{} { return e.RecipientAccountID },
}

func cloudtrailMatchPattern(event cloudtrailEvent, field string, search string) bool {
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		// fmt.Printf("need to find %s in event.%s[\"%s\"]\n", search, parts[0], parts[1])
		return strings.Contains(cloudtrailEventField[parts[0]](&event).(map[string]interface{})[parts[1]].(string), search)
	} else {
		// fmt.Printf("need to find %s in event.%s\n", search, field)
		return strings.Contains(cloudtrailEventField[field](&event).(string), search)
	}
	return false
}
