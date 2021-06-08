import pytest

from rpkiclientweb.util import parse_host, validate


def test_parse_legacy_format():
    res = parse_host("rpki.cnnic.cn/rpki/A9162E3D0000/1587/h6wAjnaB0p2pptlBZ4bkOwowMM8.roa")
    assert res == "rpki.cnnic.cn"

def test_rrdp_format():
    res = parse_host("rrdp/73885635ed28814800212d730ae80581fc5112c4b5804a08d55d6bda2afa1615/ca.rg.net/rpki/RGnet-OU/ovsCA/IOUcOeBGM_Tb4dwfvswY4bnNZYY.mft")
    assert res == "ca.rg.net"

def test_rsync_format():
    res = parse_host("rsync/rpki.apnic.net/repository/838DB214166511E2B3BC286172FD1FF2/C5zKkN0Neoo3ZmsZIX_g2EA3t6I.mft:")
    assert res == "rpki.apnic.net"


def test_validate_passes():
    res = validate(True, "should not raise")
    assert res is None

def test_validate_raises():
    with pytest.raises(ValueError):
        validate(False, "should raise")

def test_validate_raises_template():
    with pytest.raises(ValueError):
        validate(False, "should raise {}", "and template")

