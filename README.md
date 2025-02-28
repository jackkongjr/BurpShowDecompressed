# BurpShowDecompressed BurpSuite Extension
Show file list response contains compressed file

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

![image](https://github.com/user-attachments/assets/e854eab3-49f1-40be-a0ef-e4845b39557c)
