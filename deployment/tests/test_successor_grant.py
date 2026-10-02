import importlib.util
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "successor_grant", Path(__file__).parents[1] / "successor_grant.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class ProductionWriterShapeTest(unittest.TestCase):
    def base(self):
        return {
            "MinSize": 0,
            "MaxSize": 1,
            "DesiredCapacity": 1,
            "Instances": [{"LifecycleState": "InService"}],
        }

    def test_accepts_capacity_zero_floor_with_one_live_writer(self):
        self.assertTrue(MODULE.production_writer_is_single_and_live(self.base()))

    def test_rejects_nonzero_minimum_that_would_prevent_safe_capacity_zero(self):
        group = self.base()
        group["MinSize"] = 1
        self.assertFalse(MODULE.production_writer_is_single_and_live(group))

    def test_rejects_more_than_one_possible_or_observed_writer(self):
        for field, value in (("MaxSize", 2), ("DesiredCapacity", 0)):
            group = self.base()
            group[field] = value
            self.assertFalse(MODULE.production_writer_is_single_and_live(group))
        group = self.base()
        group["Instances"].append({"LifecycleState": "InService"})
        self.assertFalse(MODULE.production_writer_is_single_and_live(group))

    def test_rejects_writer_that_is_not_in_service(self):
        group = self.base()
        group["Instances"][0]["LifecycleState"] = "Pending"
        self.assertFalse(MODULE.production_writer_is_single_and_live(group))


class RuntimeMeasurementChangeTest(unittest.TestCase):
    def test_hot_renewal_is_not_a_runtime_change(self):
        binding = {"amiId": "ami-current", "pcr0": "current"}
        self.assertFalse(MODULE.runtime_measurement_changed({"runtimeMeasurement": binding.copy()}, binding))

    def test_new_ami_is_a_runtime_change(self):
        current = {"runtimeMeasurement": {"amiId": "ami-current", "pcr0": "current"}}
        candidate = {"amiId": "ami-next", "pcr0": "next"}
        self.assertTrue(MODULE.runtime_measurement_changed(current, candidate))


if __name__ == "__main__":
    unittest.main()
