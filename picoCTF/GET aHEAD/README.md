# GET aHEAD

## 解法
同じindex.phpにアクセスするが背景色が異なっている。ソースコードを確認するとメソッドがGETとPOSTで異なっていた。

ヒントにこれ以外にもメソッドがあるよ！と書いていたので調べると

PUT, DELETE, HEAD, OPTIONS, TRACE, CONNECTがあるようで前から試していくとPUT, DELETEのときは背景色が白色になり、HEADのときはそもそもページが表示されなかった。Inspectorで調べるとフラグがあった。

```
picoCTF{r3j3ct_th3_du4l1ty_8f878508}
```