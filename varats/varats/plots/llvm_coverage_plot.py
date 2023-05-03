"""Display the coverage data."""

from __future__ import annotations

import typing as tp
from collections import defaultdict
from copy import deepcopy
from itertools import filterfalse

from more_itertools import powerset

from varats.base.configuration import (
    PlainCommandlineConfiguration,
    Configuration,
)
from varats.data.reports.llvm_coverage_report import CoverageReport, cov_show
from varats.paper.case_study import CaseStudy
from varats.paper.paper_config import get_loaded_paper_config
from varats.paper_mgmt.case_study import get_case_study_file_name_filter
from varats.plot.plot import Plot
from varats.plot.plots import PlotGenerator
from varats.report.report import ReportFilepath
from varats.revision.revisions import get_processed_revisions_files
from varats.ts_utils.click_param_types import (
    REQUIRE_MULTI_EXPERIMENT_TYPE,
    REQUIRE_MULTI_CASE_STUDY,
)
from varats.utils.config import load_configuration_map_for_case_study
from varats.utils.git_util import FullCommitHash, RepositoryAtCommit
"""
@dataclass(frozen=True)
class ConfigValue:
    \"""Wrapper for config flag values.\"""

    x: tp.Union[bool, str]

    def __bool__(self) -> bool:
        if isinstance(self.x, bool):
            return self.x
        if isinstance(self.x, str):
            return True
        raise NotImplementedError()

    def __repr__(self) -> str:
        return repr(self.x)
"""
"""
class RunConfig(tp.FrozenSet[tp.Tuple[str, ConfigValue]]):
    \"""All features that were enabled/disabled during one run.\"""

    @classmethod
    def from_configuration(
        cls, configuration: Configuration, available_features: tp.Set[str]
    ) -> RunConfig:
        \"""Create RunConfig from Configuration.\"""
        result = get_features(configuration)
        # Set all not given features to false
        for feature in available_features.difference(set(result)):
            result[feature] = False

        return cls(result)

    def __new__(cls, features: tp.Dict[str, tp.Union[bool, str]]) -> RunConfig:
        return super().__new__(
            cls,
            (
                (feature, ConfigValue(value))  # type: ignore
                for feature, value in features.items()
            )
        )

    def keys(self) -> tp.Iterator[str]:
        for item in self:
            yield item[0]

    def values(self) -> tp.Iterator[ConfigValue]:
        for item in self:
            yield item[1]

    def items(self) -> tp.Iterator[tp.Tuple[str, ConfigValue]]:
        return iter(self)

    def get(self, feature: str) -> tp.Optional[ConfigValue]:
        \"""Returns either value of feature or None.\"""
        for item in self:
            if item[0] == feature:
                return item[1]

        return None

    def contains(self, feature: str, value: ConfigValue) -> bool:
        return (feature, value) in self

    def __repr__(self) -> str:
        tmp = list(str(x) for x in self)
        return f"|{', '.join(tmp)}|"
"""


class ConfigCoverageReportMapping(tp.Dict[Configuration, CoverageReport]):
    """Maps RunConfigs to CoverageReports."""

    def __init__(
        self, dictionary: tp.Dict[Configuration, CoverageReport]
    ) -> None:
        available_features = set()
        for config in dictionary:
            for feature in config.option_names():
                available_features.add(feature)
        self.available_features = frozenset(available_features)

        tmp = {}
        for configuration, report in dictionary.items():
            # Recreate configuration with missing features
            new_configuration = deepcopy(configuration)
            for option_name in available_features.difference(
                set(configuration.option_names())
            ):
                # Option was not given. Assume this corresponds to value False.
                new_configuration.set_config_option(option_name, False)
            new_configuration = new_configuration.freeze()
            tmp[new_configuration] = report

        super().__init__(tmp)

    def create_feature_filter(
        self, features: tp.Dict[str, bool]
    ) -> tp.Callable[[Configuration], bool]:
        """Create filter for the given features."""

        def feature_filter(config: Configuration) -> bool:
            """filter all configs that contain the given features."""
            for feature, value in features.items():
                if not config.contains(feature, value):
                    return False
            return True

        return feature_filter

    def _get_configs_with_features(
        self, features: tp.Dict[str, bool]
    ) -> tp.List[Configuration]:
        feature_filter = self.create_feature_filter(features)
        return list(filter(feature_filter, list(self)))

    def _get_configs_without_features(
        self, features: tp.Dict[str, bool]
    ) -> tp.List[Configuration]:
        feature_filter = self.create_feature_filter(features)
        return list(filterfalse(feature_filter, list(self)))

    def diff(self, features: tp.Dict[str, bool]) -> CoverageReport:
        """Creates a coverage report by diffing all coverage reports that
        contain the given features with all that do not share them."""

        for feature in features:
            if feature not in self.available_features:
                raise ValueError(
                    f"No reports with feature '{feature}' available!"
                )

        configs_with_features = self._get_configs_with_features(features)
        configs_without_features = self._get_configs_without_features(features)

        _ = ','.join("\n" + str(set(x)) for x in configs_with_features)
        print(f"Configs with features:\n[{_}\n]")

        _ = ','.join("\n" + str(set(x)) for x in configs_without_features)
        print(f"Configs without features:\n[{_}\n]")

        if len(configs_with_features
              ) == 0 or len(configs_without_features) == 0:
            raise ValueError(
                "Diff impossible! No reports with given features available!"
            )

        report_with_features = _merge_reports(
            list(deepcopy(self[x]) for x in configs_with_features)
        )

        result = _merge_reports(
            list(deepcopy(self[x]) for x in configs_without_features)
        )

        result.diff(report_with_features)
        return result

    def merge_all(self) -> CoverageReport:
        """Merge all available Reports into one."""
        return _merge_reports(deepcopy(list(self.values())))


BinaryConfigsMapping = tp.NewType(
    "BinaryConfigsMapping", tp.Dict[str, ConfigCoverageReportMapping]
)
"""
def get_features(
    configuration: Configuration
) -> tp.Dict[str, tp.Union[str, bool]]:
    \"""Convert all options in configuration to dict.\"""
    result: tp.Dict[str, tp.Union[str, bool]] = {}
    for option in configuration.options():
        if option.name != "UNKNOWN":
            result[option.name] = option.value
        else:
            splitted = option.value.split(maxsplit=1)
            result[splitted[0]] = splitted[1] if len(splitted) > 1 else True
    return result
"""


def non_empty_powerset(iterable: tp.Iterable[tp.Any]) -> tp.Iterable[tp.Any]:
    """Powerset without empty set."""
    iterator = powerset(iterable)
    next(iterator)
    return iterator


def _merge_reports(reports: tp.Iterable[CoverageReport]) -> CoverageReport:
    reports = iter(reports)
    report = next(reports)
    for coverage_report in reports:
        report.merge(coverage_report)
    return report


class CoveragePlot(Plot, plot_name="coverage"):
    """Plot to visualize coverage diffs."""

    def _get_binary_config_map(
        self, case_study: CaseStudy, report_files: tp.List[ReportFilepath]
    ) -> tp.Optional[BinaryConfigsMapping]:

        try:
            config_map = load_configuration_map_for_case_study(
                get_loaded_paper_config(), case_study,
                PlainCommandlineConfiguration
            )
        except StopIteration:
            return None

        binary_config_map: tp.DefaultDict[str, tp.Dict[
            Configuration, CoverageReport]] = defaultdict(dict)

        for report_filepath in report_files:
            binary = report_filepath.report_filename.binary_name
            config_id = report_filepath.report_filename.config_id
            assert config_id is not None

            coverage_report = CoverageReport.from_report(
                report_filepath.full_path()
            )
            config = config_map.get_configuration(config_id).freeze()
            assert config is not None
            binary_config_map[binary][config] = coverage_report

        result = {}
        for binary in list(binary_config_map):
            result[binary] = ConfigCoverageReportMapping(
                binary_config_map[binary]
            )
        return BinaryConfigsMapping(result)

    def plot(self, view_mode: bool) -> None:
        if len(self.plot_kwargs["experiment_type"]) > 1:
            print(
                "Plot can currently only handle a single experiment, "
                "ignoring everything else."
            )

        case_study = self.plot_kwargs["case_study"]

        project_name = case_study.project_name

        report_files = get_processed_revisions_files(
            project_name,
            self.plot_kwargs["experiment_type"][0],
            CoverageReport,
            get_case_study_file_name_filter(case_study),
            only_newest=False,
        )

        revisions = defaultdict(list)
        for report_file in report_files:
            revision = report_file.report_filename.commit_hash
            revisions[revision].append(report_file)

        for revision in list(revisions):
            binary_config_map = self._get_binary_config_map(
                case_study, revisions[revision]
            )

            if not binary_config_map:
                raise ValueError(
                    "Cannot load configs for case study '" +
                    case_study.project_name + "'! " +
                    "Have you set configs in your case study file?"
                )

            with RepositoryAtCommit(project_name, revision) as base_dir:
                for binary in binary_config_map:
                    config_report_map = binary_config_map[binary]

                    print("Code executed by all feature combinations")
                    print(cov_show(config_report_map.merge_all(), base_dir))
                    for features in non_empty_powerset(
                        config_report_map.available_features
                    ):
                        print(f"Diff for '{features}':")
                        diff = config_report_map.diff({
                            feature: True for feature in features
                        })
                        print(cov_show(diff, base_dir))

    def calc_missing_revisions(
        self, boundary_gradient: float
    ) -> tp.Set[FullCommitHash]:
        raise NotImplementedError


class CoveragePlotGenerator(
    PlotGenerator,
    generator_name="coverage",
    options=[REQUIRE_MULTI_EXPERIMENT_TYPE, REQUIRE_MULTI_CASE_STUDY]
):
    """Generates repo-churn plot(s) for the selected case study(ies)."""

    def generate(self) -> tp.List[Plot]:
        result: tp.List[Plot] = []
        for case_study in self.plot_kwargs["case_study"]:
            plot_kwargs = deepcopy(self.plot_kwargs)
            plot_kwargs["case_study"] = deepcopy(case_study)
            result.append(CoveragePlot(self.plot_config, **plot_kwargs))
        return result
