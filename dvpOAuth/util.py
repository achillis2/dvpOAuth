
SEARCH_BASE_URL = 'https://ccapimqa.apimanagement.us21.hana.ondemand.com/v1/cc/DSMVendorsInboundServices/ZAcctSearchAndRetrieveSet'
                   
SEARCH_PAR = "InternetFunctionCode eq 'ACCTSRCH' and "

RESULT_LOOKUP = {
    'S': 'S - Successful - The call was successful, and the reply contains appropriate results.',
    'W': 'W - Warning - The call was successful, but a warning message was generated.',
    'U': 'U - Unsatisfactory - The call was not completed successfully and/or no result set has been returned.',
    'F': 'F - Failure - There was an unrecoverable program error.',
    'D': 'D - Disabled - The specific function requested is not available at this time.',
}