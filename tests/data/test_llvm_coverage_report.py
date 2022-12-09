import unittest
from copy import deepcopy

from varats.experiments.vara.llvm_coverage_experiment import (
    CodeRegion,
    CodeRegionKind,
)

CODE_REGION_1 = CodeRegion.from_list([9, 79, 17, 2, 4, 0, 0, 0], "main")


class TestCodeRegion(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.CODE_REGION_1 = CodeRegion(
            start_line=9,
            start_column=79,
            end_line=17,
            end_column=2,
            count=4,
            kind=CodeRegionKind.CODE,
            function="main"
        )
        self.CODE_REGION_2 = CodeRegion(
            start_line=9,
            start_column=80,
            end_line=17,
            end_column=1,
            count=0,
            kind=CodeRegionKind.CODE,
            function="main"
        )
        self.CODE_REGION_1.insert(self.CODE_REGION_2)

        self.root = CodeRegion.from_list([0, 0, 100, 100, 5, 0, 0, 0], "main")
        self.left = CodeRegion.from_list([0, 1, 49, 100, 5, 0, 0, 0], "main")
        self.right = CodeRegion.from_list([50, 0, 100, 99, 5, 0, 0, 0], "main")
        self.left_left = CodeRegion.from_list([30, 0, 40, 100, 3, 0, 0, 0],
                                              "main")
        self.left_left_2 = CodeRegion.from_list([10, 0, 20, 100, 3, 0, 0, 0],
                                                "main")
        self.right_right = CodeRegion.from_list([60, 0, 80, 100, 2, 0, 0, 0],
                                                "main")

        self.root.insert(self.right)
        self.root.insert(self.left_left)
        self.root.insert(self.left_left_2)
        self.root.insert(self.left)
        self.root.insert(self.right_right)

    def test_eq(self):
        self.assertEqual(self.CODE_REGION_1, CODE_REGION_1)

    def test_not_eq_1(self):
        self.CODE_REGION_1.start_line = 1
        self.assertNotEqual(self.CODE_REGION_1, CODE_REGION_1)

    def test_not_eq_2(self):
        self.CODE_REGION_1.end_line = 18
        self.assertNotEqual(self.CODE_REGION_1, CODE_REGION_1)

    def test_not_eq_3(self):
        self.CODE_REGION_1.end_column = 1
        self.assertNotEqual(self.CODE_REGION_1, CODE_REGION_1)

    def test_not_eq_4(self):
        self.CODE_REGION_1.kind = CodeRegionKind.GAP
        self.assertNotEqual(self.CODE_REGION_1, CODE_REGION_1)

    def test_less_1(self):
        self.assertFalse(self.CODE_REGION_1 < CODE_REGION_1)
        self.assertTrue(self.CODE_REGION_1 <= CODE_REGION_1)

        self.CODE_REGION_1.start_column = 78
        self.assertTrue(self.CODE_REGION_1 < CODE_REGION_1)
        self.assertFalse(CODE_REGION_1 < self.CODE_REGION_1)

    def test_greater_1(self):
        self.assertFalse(self.CODE_REGION_1 > CODE_REGION_1)
        self.assertTrue(self.CODE_REGION_1 >= CODE_REGION_1)

        self.CODE_REGION_1.start_column = 80
        self.assertTrue(self.CODE_REGION_1 > CODE_REGION_1)
        self.assertFalse(CODE_REGION_1 > self.CODE_REGION_1)

    def test_subregions(self):
        self.assertFalse(self.CODE_REGION_1.is_subregion(self.CODE_REGION_1))

        self.assertTrue(self.CODE_REGION_1.is_subregion(self.CODE_REGION_2))
        self.assertFalse(self.CODE_REGION_2.is_subregion(self.CODE_REGION_1))

        self.CODE_REGION_1.start_line = 10
        self.CODE_REGION_2.end_column = 2
        self.assertFalse(self.CODE_REGION_1.is_subregion(self.CODE_REGION_2))
        self.assertFalse(self.CODE_REGION_2.is_subregion(self.CODE_REGION_1))

    def test_is_covered(self):
        self.assertTrue(self.CODE_REGION_1.is_covered())
        self.assertFalse(self.CODE_REGION_2.is_covered())

    def test_contains(self):
        self.assertTrue(self.CODE_REGION_2 in self.CODE_REGION_1)
        self.assertFalse(self.CODE_REGION_1 in self.CODE_REGION_2)

    def test_parent(self):
        self.assertFalse(self.CODE_REGION_1.has_parent())
        self.assertIsNone(self.CODE_REGION_1.parent)

        self.assertTrue(self.CODE_REGION_2.has_parent())
        self.assertEqual(self.CODE_REGION_2.parent, self.CODE_REGION_1)

    def test_iter_breadth_first(self):
        self.assertEqual([
            self.root, self.left, self.right, self.left_left_2, self.left_left,
            self.right_right
        ], [x for x in self.root.iter_breadth_first()])

    def test_iter_postorder(self):
        self.assertEqual([
            self.left_left_2, self.left_left, self.left, self.right_right,
            self.right, self.root
        ], [x for x in self.root.iter_postorder()])

    def test_insert(self):
        self.assertTrue(self.root.is_subregion(self.left))
        self.assertTrue(self.root.is_subregion(self.right))
        self.assertTrue(self.root.is_subregion(self.left_left))
        self.assertTrue(self.root.is_subregion(self.right_right))
        self.assertTrue(self.left.is_subregion(self.left_left))
        self.assertTrue(self.left.is_subregion(self.left_left_2))
        self.assertTrue(self.right.is_subregion(self.right_right))

        self.assertFalse(self.right.is_subregion(self.left))
        self.assertFalse(self.right.is_subregion(self.left_left))
        self.assertFalse(self.right.is_subregion(self.left_left_2))
        self.assertFalse(self.left.is_subregion(self.right))
        self.assertFalse(self.left.is_subregion(self.right_right))
        self.assertFalse(self.left.is_subregion(self.root))
        self.assertFalse(self.right.is_subregion(self.root))

        self.assertTrue(self.left.parent is self.root)
        self.assertTrue(self.right.parent is self.root)
        self.assertTrue(self.left_left.parent is self.left)
        self.assertTrue(self.left_left_2.parent is self.left)
        self.assertTrue(self.right_right.parent is self.right)

    def test_diff(self):
        root_2 = deepcopy(self.root)
        root_3 = deepcopy(self.root)

        root_2.diff(root_3)

        for x in root_2.iter_breadth_first():
            self.assertEqual(x.count, 0)

        self.left_left.count = 5
        self.left_left_2.count = 1
        self.right_right.count = 3

        self.root.diff(root_3)
        self.assertEqual(self.root.count, 0)
        self.assertEqual(self.right.count, 0)
        self.assertEqual(self.left.count, 0)
        self.assertEqual(self.left_left.count, 2)
        self.assertEqual(self.left_left_2.count, -2)
        self.assertEqual(self.right_right.count, 1)
