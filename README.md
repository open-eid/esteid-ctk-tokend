# esteid-ctk-tokend

 * License: LGPL 2.1
 * &copy; Estonian Information System Authority
 * [Architecture of ID-software](http://open-eid.github.io)

## Components

 * EstEIDToken - CTK tokend extension implementation
 * EstEIDTokenApp - Blank application, contains CTK tokend extension

## Building
[![Build Status](https://travis-ci.org/open-eid/esteid-ctk-tokend.svg?branch=master)](https://travis-ci.org/open-eid/esteid-ctk-tokend)
 
 1. Install dependencies from
   * [XCode](https://itunes.apple.com/en/app/xcode/id497799835?mt=12)

 2. Fetch the source

        git clone --recursive https://github.com/open-eid/esteid-ctk-tokend
        cd esteid-ctk-tokend

 3. Build

        xcodebuild -project EstEIDTokenApp.xcodeproj build

 4. Usage

        Execute blank "EstEIDTokenApp.app" application and it registers the extension.
        Open Safari and use site with client certificate requirement.

 5. Debug

        Open Console.app and filter EstEID logs
        Load extension
        pluginkit -a EstEIDTokenApp.app/Contents/PlugIns/EstEIDToken.appex
        Unload extension
        pluginkit -r EstEIDTokenApp.app/Contents/PlugIns/EstEIDToken.appex
        List cards
        security list-smartcard
        List card parameters
        security export-smartcard
        Kill daemon
        ps aux |grep EstEIDToken.appex
        kill -9 PID

## References
* Apple example code https://developer.apple.com/library/content/samplecode/PIVToken/Introduction/Intro.html
* Belgium implementation https://github.com/Fedict/eid-mw/tree/master/cardcomm/ctkToken
* OpenSC implementation https://github.com/frankmorgner/OpenSCToken

## Support
Official builds are provided through official distribution point [installer.id.ee](https://installer.id.ee). If you want support, you need to be using official builds. Contact for assistance by email [abi@id.ee](mailto:abi@id.ee) or [www.id.ee](http://www.id.ee).

Source code is provided on "as is" terms with no warranty (see license for more information). Do not file Github issues with generic support requests.
