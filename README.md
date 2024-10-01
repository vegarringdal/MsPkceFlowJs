# MsPkceFlowJs

Wanted to learn more about auth 2.0 pkce flow for SPA apps.
Maybe create a very simple class you can copy to project with no dependencies

Todo:
* [ ] remove weird callback and have event listener
* [ ] activate to return {success, data, error}, prob always do this on all internal too
* [ ] maybe add multi account logic?
* [ ] Im able to call refresh token, though we could not do this/why msal used hidden iframe and is unuasable with COEP/COOP headers, check out this more..


Ref:
https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-auth-code-flow



# getting started

* install nodejs
* run `npm i`
* run `npm start`
* open browser at `http://localhost:8080`

