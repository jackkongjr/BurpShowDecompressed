# BurpShowDecompressed BurpSuite Extension
Show file list response contains compressed file


#### Changelog

 - 01/03/2025 - Added search field and browsing over tree view
 - 28/02/2025 - first commit


#### Compile


```
javac -cp burpsuite_community.jar BurpShowDecompressed.java

jar cf BurpShowDecompressed.jar BurpShowDecompressed.class BurpShowDecompressed\$DecompressTab.class BurpShowDecompressed\$DecompressTab\$TreeNode.class 

```

#### Install

```
Go to BurpSuite -> Extensions -> Installed -> Add
Select compiled .jar file
Done

```

#### Usage

```
When a response contains a compressed file you can switch to Decompressed tab and view the file list

```



![image](https://github.com/user-attachments/assets/d9c527c1-de9d-4bcf-81db-90520825fae2)

