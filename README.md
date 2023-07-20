# WebHooks Proxy

Receives webhook calls and sends them to any subscriber to /sse or to /signalr endpoints.

Requieres a SECRET_KEY environment variable to be 32 characters.

Any webhook call will be encrypted with AES-GCM and serialized with Base64 and sent to subscribers.
