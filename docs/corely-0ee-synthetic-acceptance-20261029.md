# Corely DEV 0ee 單次合成驗收

日期：2026-10-29（Asia/Taipei）。Executor runtime 固定 `0ee877a2c427d1c200a91ba033f11b710641b433`，本文件提交不是新 runtime／部署授權。

- 精確CI40735399902成功後，依Owner批准只換專用VM executor；Go同原immutable image，僅為新私有CA短重建，Caddy／PostgreSQL／Redis不重建。Corely candidate仍2e57809a，正常DEV及正式站不變。
- 正常建立普通user6 `siwc-0ee877a2`／Sol-only有限23h token5／channel5與exact token+model+Responses strict路由；沒有provider API key或API備援。Corely正常VM合成同意綁既有公開指紋，非搬用Codex／Luna憑證。
- 相同server-owned moztech-test合成case只提交一次。job hash `dfbe5908198daced4039be601c95de6294a3329ab099b64c66b4129fa77e1215`，四用途的5次呼叫全部Info／`siwc_plan`／`gpt-6.1-sol`／`new_api_gateway_siwc`，獨立覆核VERIFIED，API模型0；send／learning／publish皆false。
- 精確容器＋單案例時窗＋隔離user/token/channel＋目的順序及時間佐證：HTTP5成功、VM5唯一成功、Go5個Responses200、usage5consume／error0／scope mismatch0，無restart／HELD。未取得provider逐call帳單或request ID；**官方個人方案實際扣額NOT_ATTESTED**。內部倍率0或used quota0不是供應商免費／扣額證明。
- 服務端62.223秒，舊成功單次71.164秒，少8.941秒；不是控制benchmark或品質等價證明。模型55.337秒，兩次selection16.445、decision9.202、generation8.535、review21.155；仍需後續系統級速度驗證，未取消覆核／刪知識／加單題規則。Cache metadata0，沒有cache收益證明。
- 測後token5普通正常DELETE＋logout、本機token檔移除、channel5停用、本輪route移除並正常UI儲存原三規則、Corelygrant撤銷、worker停止／round config+bridge secret+leaf key+consent+lock清理完成。原Info/Eason app-owned sessions、host／identity metadata不變。**最後普通user6停用仍待Owner正常infoadmin step-up**，不能稱整體清理完成；post資源gate待此步完成才執行。
- Eason自然額滿備援、原50題、人工改稿保存送出／學習、正常客服／全Corely切換不在本輪驗收。

主要證據在Corely owned worktree `outputs/newapi-gateway-conservative-0ee877a2/`（0600，未提交憑證或顧客內容）：

- joined verdict SHA `03178656c4b12029b9daa14e06763641a03303a9ada55a459294228c7586955e`。
- VM一次readback SHA `8eb373d0fa84d22a020874b45de27185ffb5690d258ad105acbc8093cf2f6b33`。
- VM cleanup SHA `e46cfaa47a4b488123889c48cb05fe09d0e0974d2d9808914b1a86e9c13dc3b7`。
- 測後9服務scope不變 SHA `962acad23d8b68ffe81e37624e9184ae58e983955648e9dc32095be6aa38c8e3`。

觀察器合併snapshot budget拒收時保留全部60筆已嚴格投影observations、0contract rejection，不重跑模型；操作期初quota換算與本機Node路徑首敗另在Corely交接保留，不洗掉首失敗。此記錄只驗證個人方案授權來源與合成執行，不聲稱整體ASVS合規或官方扣額核銷。
