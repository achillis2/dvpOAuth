# OAuth API for Dominion API

This package provides the following functionalities:

- Authentication
- Eligibility
- Usage
- Account Search
- Retrieve Account


You will first need to obtain an Authorization token.  This token has a 10 minute expiration.  First make a POST request to the Authentication URL with the following parameters.

NOTE: The authroization value is a Base64 string in the following format ClientID:ClientSecret

