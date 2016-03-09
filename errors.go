package saaspass

import "errors"

var (
	INVALID_RESOURCE_ID              = errors.New("Invalid resource ID")
	EMPTY_OR_NULL_VALUE              = errors.New("Empty or null parameter value sent in request.")
	MAX_LENGTH_EXCEEDED              = errors.New("Maximum parameter length exceeded.")
	INVALID_PARAMETER_VALUE          = errors.New("Invalid parameter value.")
	APPLICATION_NOT_FOUND            = errors.New("Application not found.")
	TRACKER_NOT_FOUND                = errors.New("The specified tracker was not found.")
	TRACKER_EXPIRED                  = errors.New("Tracker has expired.")
	INVALID_OTP                      = errors.New("The provided OTP is invalid.")
	NO_DEVICE_FOUND                  = errors.New("No active device found for user.")
	INVALID_IP                       = errors.New("OTP check not allowed from this IP address.")
	APPLICATION_NOT_ACTIVE           = errors.New("Application is not active.")
	INVALID_CREDENTIALS              = errors.New("Invalid authentication credentials.")
	EXPIRED_TOKEN                    = errors.New("The provided token has expired. Please re­authenticate.")
	ACTION_FORBIDDEN_FOR_APPLICATION = errors.New("Action forbidden for this application.")
	USER_NOT_ASSIGNED_TO_APPLICATION = errors.New("User not assigned to application")
	USER_NOT_ASSIGNED_TO_COMPANY     = errors.New("User not assigned to company.")
	SAASPASS_SERVER_ERROR            = errors.New("SAASPASS internal server error. Please try again.")
)
