# MEANStackAuthentication

==
- Download and Install NodeJS

- In Intellij add Angular and NodeJS Plugins

==
Mongo

- install MongoDb and add to PAth Variable
// starts mongo db and points to our project
- mongod -dbpath %ProjectDir%\MEANStackAuthentication\data or
- or create a c:\data\db folder and just run  in a cmd mongod
- Intellij: Configure Mongo Server under Settings

==

In Intellij after checking out the project locally
- import the project 
- npm install
-- This will install all the dependecies in tha package.json file to your project
-- for bower it is required git installed and added to PATH System Variable)
- npm install -g bower


==
For autocomplete in Intellij:
Right-click: Use Javascript Library > Express, Mongoose etc

== 
npm install -g bower (required git installed and added to PATH System Variable)

bower install

== 

Run project by:

node ./bin/www (you can find it in package.json)

or Right-click on the app.js and run it
==

===
Typescript

- generate the file after changes
tsc greeter.ts 


Access it via the link http://localhost:3000



