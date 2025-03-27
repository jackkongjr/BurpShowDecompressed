# BurpShowDecompressed BurpSuite Extension
Show file list if the Burp response tab contains a compressed archive


#### Changelog

 - 27/03/2025 - Added support for tar.gz archive
 - 01/03/2025 - Added search field and browsing over tree view
 - 28/02/2025 - first commit


#### Compile


```
 - use jdk version >= 22

javac -cp burpsuite_community.jar BurpShowDecompressed.java

jar cf BurpShowDecompressed.jar *.class

```

#### Install

```
Go to BurpSuite -> Extensions -> Installed -> Add
Select compiled .jar file
Done

```

#### Usage

```
When a response contains a compressed file you can switch to Decompress tab and view the file list

```



![image](https://github.com/user-attachments/assets/d9c527c1-de9d-4bcf-81db-90520825fae2)

