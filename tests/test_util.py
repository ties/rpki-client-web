import pytest

from rpkiclientweb.util import parse_host, validate
from rpkiclientweb.util.misc import parse_proto_host_from_url
from rpkiclientweb.util.prometheus import ListCollector


def test_parse_legacy_format():
    res = parse_host(
        "rpki.cnnic.cn/rpki/A9162E3D0000/1587/h6wAjnaB0p2pptlBZ4bkOwowMM8.roa"
    )
    assert res == "rpki.cnnic.cn"


def test_rrdp_format():
    res = parse_host(
        "rrdp/73885635ed28814800212d730ae80581fc5112c4b5804a08d55d6bda2afa1615/ca.rg.net/rpki/RGnet-OU/ovsCA/IOUcOeBGM_Tb4dwfvswY4bnNZYY.mft"
    )
    assert res == "ca.rg.net"


def test_rrdp_dot_format():
    res = parse_host(
        ".rrdp/2A58FCECAC1BEAAECDB0232275D0A971B146A47C3E64FEF2FA46A24F5F6B1821/rpki.afrinic.net/repository/member_repository/F36EC460/ACEC2D22898111EC95D350B45A40D577/AAFC7F38899711EC8B6754755A40D577.roa"
    )
    assert res == "rpki.afrinic.net"


def test_rsync_format():
    res = parse_host(
        "rsync/rpki.apnic.net/repository/838DB214166511E2B3BC286172FD1FF2/C5zKkN0Neoo3ZmsZIX_g2EA3t6I.mft:"
    )
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


def test_list_collector() -> None:
    """Test the custom prometheus metric collector."""
    collector = ListCollector()
    # should be empty initially
    assert not collector.collect()
    collector = None


def test_parse_proto_host_from_url() -> None:
    assert parse_proto_host_from_url(None) == ""
    assert parse_proto_host_from_url("") == ""

    assert parse_proto_host_from_url("example.org") == "example.org"
    assert parse_proto_host_from_url("https://example.org") == "https://example.org"
    assert (
        parse_proto_host_from_url("https://example.org:42") == "https://example.org:42"
    )

    assert (
        parse_proto_host_from_url("https://example.org/message.txt")
        == "https://example.org"
    )

    assert (
        parse_proto_host_from_url(
            ".rsync/rsync.paas.rpki.prepdev.ripe.net/repository/fc05bbfd-23b2-44df-b180-f1878e582a05/0/F239CACE716335E7E4079F4068CCE35BD9F33D45.crl"
        )
        == "rsync.paas.rpki.prepdev.ripe.net"
    )
    assert (
        parse_proto_host_from_url(
            "rsync.paas.rpki.prepdev.ripe.net/repository/fc05bbfd-23b2-44df-b180-f1878e582a05/0/F239CACE716335E7E4079F4068CCE35BD9F33D45.crl"
        )
        == "rsync.paas.rpki.prepdev.ripe.net"
    )
