"""Test path/file related warnings."""
# pylint: disable=missing-function-docstring

from collections import Counter

from rpkiclientweb.models import LabelWarning, ManifestObjectWarning
from rpkiclientweb.outputparser import OutputParser

from .util import parse_output_file


def test_twnic_revoked_objects() -> None:
    """
    Parse the output on 2021-2-3 that contains revoked objects.
    """
    parser = parse_output_file("inputs/20210206_sample_twnic_during.txt")

    assert (
        LabelWarning(
            warning_type="ee_certificate_revoked",
            uri="rpkica.twnic.tw/rpki/TWNICCA/OPENRICH/mlhIJnN1dfbOEvjGTcE83FLq17Q.roa",
        )
        in parser.warnings
    )


def test_overclaiming_line() -> None:
    parser = OutputParser(
        "rpki-client: ca.rg.net/rpki/RGnet-OU/_XrQ8TKGekuqYxq7Ev1ZflcIsWM.roa: RFC 3779 resource not subset of parent's resources"
    )

    assert (
        LabelWarning(
            warning_type="overclaiming",
            uri="ca.rg.net/rpki/RGnet-OU/_XrQ8TKGekuqYxq7Ev1ZflcIsWM.roa",
        )
        in parser.warnings
    )


def test_6487_uncovered_ip() -> None:
    parser = OutputParser(
        "rpki-client: .rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3DA57AAA8E/rpki.example.org/repository/DEFAULT/2RsBUBqyS0jqZooobKXoMQpCNNE.cer: RFC 6487: uncovered IP: (inherit)"
    )

    uri = ".rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3DA57AAA8E/rpki.example.org/repository/DEFAULT/2RsBUBqyS0jqZooobKXoMQpCNNE.cer"

    assert LabelWarning(warning_type="rfc6487_uncovered_ip", uri=uri) in parser.warnings


def test_6487_unknown_error() -> None:
    parser = OutputParser(
        "rpki-client: .rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3DA57AAA8E/rpki.example.org/repository/DEFAULT/2RsBUBqyS0jqZooobKXoMQpCNNE.cer: RFC 6487: other hypothetical error: (param)"
    )

    uri = ".rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3DA57AAA8E/rpki.example.org/repository/DEFAULT/2RsBUBqyS0jqZooobKXoMQpCNNE.cer"

    assert (
        LabelWarning(warning_type="rfc6487_unknown_error", uri=uri) in parser.warnings
    )


def test_rpki_object_no_valid_mft_available() -> None:
    """No valid manifest available errors."""
    res = parse_output_file("inputs/20220223_no_valid_mft_available.txt")

    assert (
        LabelWarning(
            warning_type="no_valid_mft_available",
            uri="0.sb/repo/sb/30/F8CE54A4C62E61B125423FA90CA3F9D8350C7D3D.mft",
        )
        in res.warnings
    )


def test_rpki_object_missing_sia() -> None:
    """No valid manifest available errors."""
    res = parse_output_file("inputs/20220122_missing_sia.txt")

    assert (
        LabelWarning(
            warning_type="missing_sia",
            uri="rrdp/436fc6bd7b32853e42fce5fd95b31d5e3ec1c32c46b7518c2067d568e7eac119/chloe.sobornost.net/rpki/RIPE-nljobsnijders/voibVdC3Nzl9dcSfSFuFj6mK0R8.cer",
        )
        in res.warnings
    )


def test_crl_has_expired_error() -> None:
    """Test parse 'crl has expired' errors #97"""
    res = parse_output_file("inputs/20230509_crl_has_expired.txt")
    assert (
        LabelWarning(
            warning_type="mft_crl_expired",
            uri="rpki-repo.registro.br/repo/2qosEFHVQbeQvy8iktdNzpWNHKcB1zeV4mSd6F1ea1WN/0/028B43AD112899168CE5212FE3FB097B8D664FD2.mft",
        )
        in res.warnings
    )


def test_both_possibilities_of_file_present_error() -> None:
    """Test both possibilities of file present error #88"""
    res = parse_output_file("inputs/20230328_both_possibilities_of_file_present.txt")
    assert (
        LabelWarning(
            warning_type="both_possibilities_file_present",
            uri="rpki.ml/repository/DEFAULT/02iM0p2w53PH2dRcecOfyfjwPU8.cer",
        )
        in res.warnings
    )


def test_unsupported_filetype() -> None:
    parser = OutputParser(
        "rpki-client: rrdp/198613f16d61d95b77329eb7acdb3e1f8d1f0ec2b75e9510a7f7eacc7c3ebe19/rpki-repo.registro.br/repo/CdwCiTUGWyooJPMS1kEENXCA3aBaR67C8gcsvCd5HFU1/0/CBC415E956186D9CC61972979D5AC7B197F563BB.mft: unsupported file type for 3137372e38352e3136342e302f32322d3234203d3e203532373433.inv\n"
    )

    assert ManifestObjectWarning(
        warning_type="unsupported_filetype",
        uri="rrdp/198613f16d61d95b77329eb7acdb3e1f8d1f0ec2b75e9510a7f7eacc7c3ebe19/rpki-repo.registro.br/repo/CdwCiTUGWyooJPMS1kEENXCA3aBaR67C8gcsvCd5HFU1/0/CBC415E956186D9CC61972979D5AC7B197F563BB.mft",
        object_name="3137372e38352e3136342e302f32322d3234203d3e203532373433.inv",
    ) in list(parser.warnings)


def test_parse_mft_warning() -> None:
    parser = OutputParser(
        "rpki-client: interop/misc-objects/6C76EDB2225D11E286C4BD8F7A2F2747.roa: RFC 6488: CMS has unexpected signed attribute 1.2.840.113549.1.9.15\n"
    )

    assert (
        LabelWarning(
            "unexpected_signed_cms_attribute",
            "interop/misc-objects/6C76EDB2225D11E286C4BD8F7A2F2747.roa",
        )
        in parser.warnings
    )

    parser = OutputParser(
        "rpki-client: repository.lacnic.net/rpki/lacnic/a0c4b4a0-6417-4a7c-8758-9e6f4b0e9679/9783ac9bad2b7b922f648c90e881bf44978069ad.mft: bad message digest for aa78fd79d9a4dc5b9456cc52ce73dba02a1eabe4.roa"
    )

    # 8.4 (?) style bad message digest
    assert (
        ManifestObjectWarning(
            "bad_message_digest",
            "repository.lacnic.net/rpki/lacnic/a0c4b4a0-6417-4a7c-8758-9e6f4b0e9679/9783ac9bad2b7b922f648c90e881bf44978069ad.mft",
            "aa78fd79d9a4dc5b9456cc52ce73dba02a1eabe4.roa",
        )
        in parser.warnings
    )


def test_parse_aspa_format_error() -> None:
    """Parse and count the warnings about ASPA in profile-14 and earlier format."""
    parser = OutputParser(
        "rpki-client: .rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3D4C8C48F4/rpki.prepdev.ripe.net/repository/DEFAULT/4e/1ea101-e220-419e-a968-eaee14482c11/1/pZ2hy5MpkC3sTxpOfqebiNySzO4.asa: ASPA: failed to parse ASProviderAttestation"
    )

    assert (
        LabelWarning(
            "aspa_parse_failed",
            ".rrdp/6C7608F9DCB6B5D586E660C3B957770DA3B76B9BFA57AAA8ECD0CA3D4C8C48F4/rpki.prepdev.ripe.net/repository/DEFAULT/4e/1ea101-e220-419e-a968-eaee14482c11/1/pZ2hy5MpkC3sTxpOfqebiNySzO4.asa",
        )
    ) in parser.warnings


def test_multiple_rrdp_lines() -> None:
    parser = parse_output_file("inputs/20221118_multiple_rrdp_lines.txt")
    warnings = list(parser.warnings)
    warning_types = Counter(warning.warning_type for warning in warnings)

    assert warning_types["ee_certificate_revoked"] == 1
    assert warning_types["ee_certificate_expired"] == 1
    assert warning_types["ee_certificate_not_yet_valid"] == 7


def test_duplicate_ski_local_isssuer() -> None:
    parser = parse_output_file("inputs/20230328_duplicate_ski_local_issuer.txt")
    warnings = list(parser.warnings)

    assert len(warnings) == 5

    assert (
        LabelWarning(
            "rfc6487_duplicate_ski",
            "rpki.ml/repository/DEFAULT/0EeB0IpN5s2DX7Onj4enXAtJxbY.cer",
        )
        in parser.warnings
    )
    assert (
        LabelWarning(
            "unable_to_get_local_issuer_certificate",
            "rpki.ml/repository/DEFAULT/0CaptsnPNAUgK6l5UlpeWCfx9hg.cer",
        )
        in parser.warnings
    )

    warning_types = Counter(warning.warning_type for warning in warnings)
    assert warning_types["rfc6487_duplicate_ski"] == 3
    assert warning_types["unable_to_get_local_issuer_certificate"] == 2
