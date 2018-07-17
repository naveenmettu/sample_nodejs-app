# SSO

## Installation

Before you can use this application you need to download and configure two files from the [AT&T Adco Viewership Insights Portal]( https://directtechnology.sharepoint.com/sites/ATTAdcoViewershipInsightsPortal/Shared%20Documents/Forms/AllItems.aspx?FolderCTID=0x012000D64A0C3F66C54B4C8BF3489EF33A4430&id=%2Fsites%2FATTAdcoViewershipInsightsPortal%2FShared%20Documents%2FConfiguration):

1. `.env` - Change two settings:
  * In LDAP_SERVICE_ACCOUNT_DN, change the user name (CN) to be your full name in the DA domain
  * In LDAP_SERVICE_ACCOUNT_PASSWORD, set the password to be your `base64` encoded password. Be sure to copy any trailing equal signs (`=`) that are generated as part of the encoding process. If you've never used base64 encoding before, try https://www.base64encode.org/
2. `service-provider-config.json` - No changes necessary

Once you've downloaded and configured the files, start the app using `npm start` and point your browser to http://localhost:8080. You should get a login page. If you have access to the LaunchCG LDAP server then logging in with your domain username (minus the `DA\`) and password should succeed.
