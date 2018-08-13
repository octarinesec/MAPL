
For example:
Time of day min/max (UTC time): allow only at certain times of the day (need CURRENT_TIME extractor)
Payload size min/max: allow only certain payload sizes (need MESSAGE_SIZE extractor)
Protocol: type and other data (i.e. level of security, authorized vs unauthorized, etc).
Sender version: enable blocking of messages from certain micro-service versions
gRPC function: Regular expression?
Header: data from header
Labels: services with certain labels (conditions of this type will be expanded and translated to the corresponding services).

Extractor
A function in the proxy to extract an attribute from the message or from external sources.
Examples:
CURRENT_TIME: returns the number of seconds from midnight (UTC)
IS_AUTHENTICATED: returns TRUE for authenticated communication
SENDING_SERVICE_VERSION: returns the authenticated sender’s version

