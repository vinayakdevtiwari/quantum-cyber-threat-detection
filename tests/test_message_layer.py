import numpy as np
import pytest

from message_layer import (
    text_to_bits, bits_to_text, verify_message, apply_attack,
    transmit_bit, transmit_message, suggest_target_bits,
    ATTACK_NONE, ATTACK_FORGERY, ATTACK_REPLAY, ATTACK_CHANNEL,
    ATTACK_SUBSTITUTE,
    MAX_MESSAGE_CHARS, MIN_MESSAGE_CHARS,
    NOISE_FLOOR,
)


# --- encoding -------------------------------------------------------------

def test_ascii_roundtrip():
    for msg in ["HELLO WORLD", "TRANSFER $5000", "abc123 !@#", "ABCDEFGH", "hi"]:
        assert bits_to_text(text_to_bits(msg)) == msg


def test_bit_count_is_eight_per_char():
    assert len(text_to_bits("ABCDEFGH")) == 64
    assert len(text_to_bits("A" * 8)) == 64


def test_empty_message_rejected():
    with pytest.raises(ValueError):
        text_to_bits("")
    with pytest.raises(ValueError):
        text_to_bits("   ")


def test_overlong_message_rejected():
    with pytest.raises(ValueError):
        text_to_bits("X" * (MAX_MESSAGE_CHARS + 1))


def test_non_ascii_rejected():
    with pytest.raises(ValueError):
        text_to_bits("café")


def test_decode_marks_unprintable_bytes():
    # A byte of 0xFF has no printable form; must not raise or emit control chars.
    assert bits_to_text([1] * 8) == "."


# --- verification ---------------------------------------------------------

def test_identical_bits_verify():
    bits = [1, 0, 1, 0]
    v = verify_message(bits, bits)
    assert v["status"] == "VERIFIED"
    assert v["corrupted_count"] == 0


def test_short_messages_are_accepted():
    """
    An earlier version required MIN_MESSAGE_CHARS = 8, on the reasoning that a
    short message gives an attack too few bits to show. That blocked ordinary
    use of the channel: anyone typing "hi" was told the system did not work.
    Short messages are legitimate traffic and are now accepted.

    Their attacks are still detected -- see
    test_forgery_on_a_short_message_is_still_detected.
    """
    for msg in ["a", "hi", "ok", "yes", "no"]:
        assert len(text_to_bits(msg)) == len(msg) * 8


def test_forgery_on_a_short_message_is_still_detected():
    """
    Short messages are accepted, and that must not weaken detection.

    An attempt was made to let a couple of differing bits pass as noise on
    short messages, scaled by message length. Measured, a two-bit forgery on
    "hi" then verified clean in 20 runs out of 20. Any slack wide enough to
    excuse honest noise on a 16-bit message also excuses a forgery there, so
    the allowance is flat and small instead.

    One character is the honest exception: 8 bits cannot distinguish a single
    flip from noise by counting, and the substitution case is caught by the
    quantum witness rather than by bit counting.
    """
    for msg in ["hi", "ok", "yes", "HELLO"]:
        positions = suggest_target_bits(msg)
        result = transmit_message(msg, attack=ATTACK_FORGERY, seed=1, shots=128,
                                  target_bits=positions, inject_noise=False)
        assert result["verification"]["status"] != "VERIFIED", msg


def test_substitution_on_a_short_message_is_caught_by_the_witness():
    """
    "hi" replaced by "gay" -- the case that started all of this. The text
    arrives whole, and the witness rejects it even though only a handful of
    bits differ.
    """
    result = transmit_message("hi", attack=ATTACK_SUBSTITUTE, seed=1, shots=128,
                              substitute="gay", inject_noise=False)
    assert result["received_text"] == "gay"
    assert result["verification"]["status"] == "TAMPERED"
    assert result["witness"]["verdict"] == "FORGERY PROVEN"


def test_substitution_delivers_exact_replacement_text():
    result = transmit_message("hi", attack=ATTACK_SUBSTITUTE, substitute="bye")
    assert result["received_text"] == "bye"
    assert result["verification"]["status"] == "TAMPERED"
    assert result["witness"]["verdict"] == "FORGERY PROVEN"


def test_single_flip_is_located_even_when_below_the_alarm_threshold():
    """
    One flipped bit is reported with its position, but does not raise SUSPECT:
    a lone differing bit is within what hardware noise produces, and on a short
    message it is a large fraction of very few bits. The bit is still recorded
    in corrupted_indices so the per-bit table shows where it happened.

    Two or more flips do raise SUSPECT -- see
    test_forgery_on_a_short_message_is_still_detected.
    """
    result = transmit_message("HELLO", attack=ATTACK_FORGERY, seed=1,
                              target_bits=[0], shots=128, inject_noise=False)
    assert 0 in result["verification"]["corrupted_indices"]
    assert result["verification"]["corrupted_count"] == 1

    # Bit 0 is the high bit of character 0; bit 8 the high bit of character 1.
    # verify_message compares by position, so the second must be 8, not 16.
    result = transmit_message("HELLO", attack=ATTACK_FORGERY, seed=1,
                              target_bits=[0, 8], shots=128, inject_noise=False)
    assert result["verification"]["status"] == "SUSPECT"

    # Index reporting is unchanged by the allowance: the differing bit is
    # located regardless of whether it raises the verdict.
    original = [1, 0, 1, 0, 1]
    received = [1, 0, 0, 0, 1]
    v = verify_message(original, received)
    assert v["corrupted_indices"] == [2]
    assert v["corrupted_count"] == 1


def test_massive_corruption_is_tampered():
    original = [0] * 20
    received = [1] * 20
    v = verify_message(original, received)
    assert v["status"] == "TAMPERED"
    assert v["corrupted_count"] == 20


def test_length_mismatch_flagged():
    v = verify_message([1, 0, 1], [1, 0])
    assert v["length_mismatch"] is True
    assert v["status"] != "VERIFIED"


# --- attacks --------------------------------------------------------------

def test_no_attack_leaves_bits_untouched():
    bits = [1, 0, 1, 1]
    r = apply_attack(ATTACK_NONE, bits)
    assert r["bits"] == bits
    assert r["touched"] == []


def test_forgery_flips_only_target_bits():
    bits = [0] * 32
    r = apply_attack(ATTACK_FORGERY, bits, seed=1, target_bits=[5, 9])
    assert set(r["touched"]) == {5, 9}
    assert r["bits"][5] == 1 and r["bits"][9] == 1
    assert sum(r["bits"]) == 2


def test_forgery_ignores_out_of_range_targets():
    bits = [0] * 8
    r = apply_attack(ATTACK_FORGERY, bits, seed=1, target_bits=[999, -4])
    assert all(0 <= b < 8 for b in r["touched"])


def test_replay_substitutes_different_content():
    bits = text_to_bits("ORIGINAL MSG")
    r = apply_attack(ATTACK_REPLAY, bits, seed=1, substitute="REPLACED!!")
    assert bits_to_text(r["bits"]) != "ORIGINAL MSG"


def test_channel_manipulation_corrupts_roughly_a_fifth():
    bits = [0] * 100
    r = apply_attack(ATTACK_CHANNEL, bits, seed=3)
    assert 10 <= len(r["touched"]) <= 30


def test_unknown_attack_raises():
    with pytest.raises(ValueError):
        apply_attack("not-an-attack", [0, 1, 0])


# --- physics --------------------------------------------------------------

def test_transmit_bit_high_fidelity_noiseless():
    for bit in (0, 1):
        assert transmit_bit(bit, shots=128, noise_model=None) > 0.99


def test_honest_transmission_survives_the_channel():
    """
    The honest path must not look tampered, or the whole demo is noise.

    Real hardware noise (~2% here) legitimately flips a bit or two per
    message, so the text is not guaranteed identical. What matters is that
    the verdict stays below TAMPERED and corruption stays near the noise
    floor -- a real attack flips far more than this.
    """
    result = transmit_message("HELLO WORLD", attack=ATTACK_NONE, seed=42, shots=256)
    v = result["verification"]
    assert v["status"] != "TAMPERED"
    # ~2% of 88 bits is under 2 bits on average; allow headroom but stay far
    # below the >25% that trips TAMPERED.
    assert v["corrupted_count"] <= 4


def test_honest_channel_verifies_clean_when_noise_is_off():
    """With noise disabled an honest message must verify exactly."""
    result = transmit_message("HELLO WORLD", attack=ATTACK_NONE, seed=42,
                              shots=128, inject_noise=False)
    assert result["verification"]["status"] == "VERIFIED"
    assert result["received_text"] == "HELLO WORLD"


def test_forgery_is_detected_and_localised():
    """
    A forgery must be localised to exactly the attacked positions.

    Noise is switched OFF here, and deliberately so. With noise on, the verdict
    depends on whether the channel happened to flip a third bit: two forged bits
    on an 88-bit message is 2.3%, which sits UNDER the 2.8% NOISE_FLOOR, so the
    status flipped between VERIFIED and SUSPECT depending on luck. That made
    this test assert the noise, not the forgery.

    With the channel quiet the property is exact and deterministic -- the
    received pattern differs from the original at precisely [16, 17] -- which is
    what "localised" is supposed to mean.
    """
    result = transmit_message("HELLO WORLD", attack=ATTACK_FORGERY, seed=5,
                              target_bits=[16, 17], shots=128, inject_noise=False)
    v = result["verification"]
    assert v["corrupted_indices"] == [16, 17]
    assert v["corrupted_count"] == 2


def test_forgery_above_the_noise_floor_is_flagged():
    """
    A forgery scaled the way the room scales real ones must never read VERIFIED.

    suggest_target_bits sizes a forgery to clear NOISE_FLOOR, which is what both
    the attack console and the room actually send. This pins that the status
    flips once the damage is unambiguously larger than honest hardware noise,
    which is the property the demo depends on.
    """
    text = "HELLO WORLD"
    targets = suggest_target_bits(text, count=4)
    assert len(targets) / len(text_to_bits(text)) > NOISE_FLOOR

    for _ in range(50):
        result = transmit_message(text, attack=ATTACK_FORGERY, seed=7,
                                  target_bits=targets, shots=96)
        assert result["verification"]["status"] in ("SUSPECT", "TAMPERED")


def test_replay_changes_the_received_text():
    result = transmit_message("HELLO WORLD", attack=ATTACK_REPLAY, seed=9,
                              substitute="OTHER MESSAGE", shots=128)
    assert result["received_text"] != "HELLO WORLD"
    assert result["verification"]["status"] == "TAMPERED"


def test_substitution_delivers_attacker_text_even_when_longer():
    """
    Regression: the replacement used to be truncated to the victim's length, so
    substituting a longer string silently lost its tail -- "hi" plus "gay"
    arrived as "ga". The attacker's message must arrive intact regardless of
    which is longer.
    """
    for msg, sub in [("HI THERE", "GAY"), ("WELCOME IN", "NO"),
                     ("SHORT ONE", "A MUCH LONGER MESSAGE")]:
        bits = text_to_bits(msg)
        out = apply_attack(ATTACK_SUBSTITUTE, bits, seed=1, substitute=sub)
        assert bits_to_text(out["bits"]) == sub, (msg, sub)


def test_qubit_count_is_three_per_bit():
    result = transmit_message("ABCDEFGH", attack=ATTACK_NONE, seed=1, shots=64)
    assert result["qubit_count"] == len(text_to_bits("ABCDEFGH")) * 3


def test_result_carries_display_fields():
    r = transmit_message("HI THERE", attack=ATTACK_NONE, seed=1, shots=64)
    for key in ("message", "original_text", "received_text",
                "attack_description", "verification", "original_bits"):
        assert key in r