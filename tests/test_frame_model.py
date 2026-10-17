"""
tests/test_frame_model.py
=========================
Unit tests for aegis.core.frame_model.
Verifies deterministic stack frame memory layout modeling across x86 and x86_64.
"""

import unittest
from aegis.core.frame_model import (
    FrameSegment,
    StackFrameLayout,
    format_frame_diagram,
    model_stack_frame,
)


class TestFrameModel64Bit(unittest.TestCase):
    """Test 64-bit stack frame modeling."""

    def test_64bit_without_canary(self):
        # Buffer 64, no canary, 16-byte alignment
        # raw_locals = 64, aligned = 64, padding = 0
        # buf: 0..64, rbp: 64..72, rip: 72..80
        layout = model_stack_frame(buffer_size=64, payload_len=0, arch=64, has_canary=False)
        self.assertEqual(layout.word_size, 8)
        self.assertEqual(layout.offset_to_rbp, 64)
        self.assertEqual(layout.offset_to_rip, 72)
        self.assertEqual(layout.total_frame_size, 80)
        self.assertFalse(layout.control_flow_hijacked)
        self.assertFalse(layout.canary_triggered)

    def test_64bit_with_canary_and_padding(self):
        # Buffer 64, canary 8 (raw = 72) -> 16-byte aligned = 80
        # padding = 8
        # buf: 0..64, canary: 64..72, padding: 72..80, rbp: 80..88, rip: 88..96
        layout = model_stack_frame(buffer_size=64, payload_len=70, arch=64, has_canary=True)
        self.assertEqual(layout.offset_to_canary, 64)
        self.assertEqual(layout.offset_to_rbp, 80)
        self.assertEqual(layout.offset_to_rip, 88)
        self.assertEqual(layout.total_frame_size, 96)
        # 70 bytes hits into canary (64..72)
        self.assertTrue(layout.canary_triggered)
        self.assertFalse(layout.control_flow_hijacked)

    def test_64bit_rip_hijack(self):
        # Payload reaching rip_end (96 bytes)
        layout = model_stack_frame(buffer_size=64, payload_len=96, arch=64, has_canary=True)
        self.assertTrue(layout.control_flow_hijacked)
        rip_seg = [s for s in layout.segments if s.name == "saved_rip"][0]
        state = rip_seg.state_at(96)
        self.assertTrue(state["full_overwrite"])
        self.assertEqual(state["bytes_overwritten"], 8)


class TestFrameModel32Bit(unittest.TestCase):
    """Test 32-bit stack frame modeling."""

    def test_32bit_without_canary(self):
        # Buffer 32, no canary, 16-byte alignment
        # raw_locals = 32, aligned = 32, padding = 0
        # buf: 0..32, ebp: 32..36, eip: 36..40
        layout = model_stack_frame(buffer_size=32, payload_len=16, arch=32, has_canary=False)
        self.assertEqual(layout.word_size, 4)
        self.assertEqual(layout.offset_to_rbp, 32)
        self.assertEqual(layout.offset_to_rip, 36)
        self.assertEqual(layout.total_frame_size, 40)
        self.assertFalse(layout.control_flow_hijacked)

    def test_32bit_with_canary(self):
        # Buffer 32, canary 4 -> raw = 36 -> aligned (16) = 48 -> padding = 12
        # buf: 0..32, canary: 32..36, padding: 36..48, ebp: 48..52, eip: 52..56
        layout = model_stack_frame(buffer_size=32, payload_len=56, arch=32, has_canary=True)
        self.assertEqual(layout.offset_to_canary, 32)
        self.assertEqual(layout.offset_to_rbp, 48)
        self.assertEqual(layout.offset_to_rip, 52)
        self.assertEqual(layout.total_frame_size, 56)
        self.assertTrue(layout.control_flow_hijacked)
        self.assertTrue(layout.canary_triggered)


class TestFrameModelValidationAndOutput(unittest.TestCase):
    """Test argument validation and serialization."""

    def test_invalid_arch_raises(self):
        with self.assertRaises(ValueError):
            model_stack_frame(buffer_size=64, arch=16)

    def test_invalid_buffer_size_raises(self):
        with self.assertRaises(ValueError):
            model_stack_frame(buffer_size=0)

    def test_negative_payload_raises(self):
        with self.assertRaises(ValueError):
            model_stack_frame(buffer_size=64, payload_len=-1)

    def test_to_dict_serialization(self):
        layout = model_stack_frame(buffer_size=64, payload_len=50, arch=64)
        d = layout.to_dict()
        self.assertTrue(d["success"])
        self.assertEqual(d["buffer_size"], 64)
        self.assertIn("segments", d)
        self.assertIn("buffer", d["segments"])

    def test_format_frame_diagram(self):
        layout = model_stack_frame(buffer_size=64, payload_len=96, arch=64, has_canary=True)
        diagram_color = format_frame_diagram(layout, color=True)
        diagram_plain = format_frame_diagram(layout, color=False)
        self.assertIn("Stack Frame Boundary Model", diagram_plain)
        self.assertIn("Offset to Return Address (RIP)", diagram_plain)
        self.assertIn("INSTRUCTION POINTER HIJACK CONFIRMED", diagram_plain)
        self.assertIn("\033[", diagram_color)


if __name__ == "__main__":
    unittest.main()
