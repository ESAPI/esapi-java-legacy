# How to Build and Develop ESAPI with IntelliJ

IntelliJ is set up to run pretty seamlessly out of the box, but there are still a few configuration options we need to change in order to get Unit Tests to run properly.

1. Click `Run` > `Edit Configurations...`
2. Click `+` > `JUnit` to add a new Run Configuration for JUnit
3. Set the `Name:` field to `JUnit Config`
4. Set the `Test kind:` field to `All in package`
5. Set the `Search for tests:` field to `In whole project`
6. Set the `Working directory:` field to **your** project root directory (e.g. ~/workspace/esapi-java-legacy)

In order to Run ESAPI with Tests, you just need to select `Run` > `Run 'JUnit Config' with Coverage`

That's it!
