# Exact128 Set：完整128位键的精确集合

本仓库公开一个固定交付版本。它支持在线插入和精确查询。
当前版本为 `huawei128_wide50_w128_aux512_v1r4`。

## 从哪里开始

1. 阅读 `frozen/reference.py`。这是独立的算法模型。
2. 阅读 `frozen/rtl/`。这里保存对应的RTL实现。
3. 阅读 `docs/ALGORITHM.md` 和 `docs/VALIDATION.md`。它们说明接口和验证范围。
4. 执行只读完整性核对，再按需在原生Linux重现已记录案例。

Windows和Linux均可执行以下命令。它只核对文件、语法和统计，不执行算法。

```text
python -B tools/verify_release.py
```

以下命令仅在原生Linux执行。它使用原案例的固定种子，不产生新种子。

```text
python3 -B tools/reproduce.py --case-id 0 --output /tmp/exact128-case0.json
python3 -B tools/reproduce.py --boundary --output /tmp/exact128-boundary.json
```

第二项应重现514键反例。该检查通过表示已重现已知限制。
结果文件必须使用尚不存在的路径，并放在仓库外。

## 已有结果

十万组自建软件验证全部完成。每组包含256000个不同的完整128位键。
十类配置各有10000组。失败组数和拒绝插入数均为0。
每组冲突最低118、平均173.7251、最高235。门槛为512。
最高冲突率为0.091796875%。模型存储为原始键数据量的109.025%。

这些结果不等于华为指定输入验收。
已知514键反例仍产生513次冲突和1项拒绝。
全规模RTL、目标器件面积、时序、吞吐量和功耗仍待验证。

## 仓库范围

算法、RTL和原验证代码按文件映射保持原字节。
`frozen/verify_source.py` 与 `frozen/manifest.json` 是本次公开包装的核对文件。
`frozen/validation/baseline/` 是原验证入口所需的对照依赖。
这些依赖不作为新的推荐算法版本。
历史实验、运行队列、工具缓存、业务资料和原题截图未带入本仓库。

[发布页](https://github.com/19991111/exact128-set/releases/tag/v1r4-source)提供十万组逐组记录和一个保留输入的下载。
逐组记录保留全部原种子和输入SHA256。
原始研究仓库和完整运行归档保持独立。

固定候选提交：`133211a2efe88a1403e3d80d6e83007248936359`。
十万组结果提交：`cbdc97bbae8ecab66e9008a6622152741c31cb85`。
源码对应关系见 `SOURCE_PROVENANCE.json`。
公开版本标签为 `v1r4-source`。

本次公开没有新增代码复用许可证。原有声明保留，详见 `NOTICE.md`。
