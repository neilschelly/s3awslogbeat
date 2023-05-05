package beater

import (
	"strings"

	"github.com/elastic/beats/libbeat/logp"
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
    "eventTime": func(e *cloudtrailEvent) interface{}          { return e.EventTime },
    "eventVersion": func(e *cloudtrailEvent) interface{}       { return e.EventVersion },
    "eventSource": func(e *cloudtrailEvent) interface{}        { return e.EventSource },
    "userIdentity": func(e *cloudtrailEvent) interface{}       { return e.UserIdentity },
    "eventName": func(e *cloudtrailEvent) interface{}          { return e.EventName },
    "awsRegion": func(e *cloudtrailEvent) interface{}          { return e.AwsRegion },
    "sourceIPAddress": func(e *cloudtrailEvent) interface{}    { return e.SourceIPAddress },
    "userAgent": func(e *cloudtrailEvent) interface{}          { return e.UserAgent },
    "errorCode": func(e *cloudtrailEvent) interface{}          { return e.ErrorCode },
    "errorMessage": func(e *cloudtrailEvent) interface{}       { return e.ErrorMessage },
    "requestParameters": func(e *cloudtrailEvent) interface{}  { return e.RequestParameters },
    "requestID": func(e *cloudtrailEvent) interface{}          { return e.RequestID },
    "eventID": func(e *cloudtrailEvent) interface{}            { return e.EventID },
    "eventType": func(e *cloudtrailEvent) interface{}          { return e.EventType },
    "apiVersion": func(e *cloudtrailEvent) interface{}         { return e.APIVersion },
    "recipientAccountID": func(e *cloudtrailEvent) interface{} { return e.RecipientAccountID },
}

func cloudtrailMatchPattern(event cloudtrailEvent, field string, search string) bool {
	if strings.Contains(field, ".") {
		parts := strings.SplitN(field, ".", 2)
		logp.Debug("s3awslogbeat", "need to find %s in event.%s[\"%s\"] (RequestID: %+v)\n", search, parts[0], parts[1], event.RequestID)
		if mapToSearch := cloudtrailEventField[parts[0]](&event); mapToSearch != nil {
			logp.Debug("s3awslogbeat", "mapToSearch: %+v\n", mapToSearch)
			if fieldToSearch := mapToSearch.(map[string]interface{})[parts[1]]; fieldToSearch != nil {
				logp.Debug("s3awslogbeat", "fieldToSearch: %+v\n", fieldToSearch)
				return strings.Contains(fieldToSearch.(string), search)
			}
		}
	} else {
		logp.Debug("s3awslogbeat", "need to find %s in event.%s (RequestID: %+v)\n", search, field, event.RequestID)
		if fieldToSearch := cloudtrailEventField[field](&event); fieldToSearch != nil {
			return strings.Contains(fieldToSearch.(string), search)
		}
	}
	return false
}
