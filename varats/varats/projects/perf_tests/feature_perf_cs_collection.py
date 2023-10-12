"""Project file for the feature performance case study collection."""
import typing as tp
from pathlib import Path

import benchbuild as bb
from benchbuild.command import Command, SourceRoot, WorkloadSet
from benchbuild.source import HTTPMultiple
from benchbuild.utils.cmd import make, cmake, mkdir
from benchbuild.utils.revision_ranges import RevisionRange
from benchbuild.utils.settings import get_number_of_jobs
from plumbum import local

from varats.experiment.workload_util import (
    RSBinary,
    WorkloadCategory,
    ConfigParams,
)
from varats.paper.paper_config import project_filter_generator
from varats.project.project_domain import ProjectDomains
from varats.project.project_util import (
    ProjectBinaryWrapper,
    BinaryType,
    get_local_project_git_path,
    verify_binaries,
)
from varats.project.sources import FeatureSource
from varats.project.varats_command import VCommand
from varats.project.varats_project import VProject
from varats.utils.git_commands import init_all_submodules, update_all_submodules
from varats.utils.git_util import RevisionBinaryMap, ShortCommitHash
from varats.utils.settings import bb_cfg


def _do_feature_perf_cs_collection_compile(
    project: VProject, cmake_flag: str
) -> None:
    """Common compile function for FeaturePerfCSCollection projects."""
    feature_perf_source = local.path(project.source_of(project.primary_source))

    cc_compiler = bb.compiler.cc(project)
    cxx_compiler = bb.compiler.cxx(project)

    mkdir("-p", feature_perf_source / "build")

    init_all_submodules(Path(feature_perf_source))
    update_all_submodules(Path(feature_perf_source))

    with local.cwd(feature_perf_source / "build"):
        with local.env(CC=str(cc_compiler), CXX=str(cxx_compiler)):
            bb.watch(cmake)("..", "-G", "Unix Makefiles", f"-D{cmake_flag}=ON")

        bb.watch(make)("-j", get_number_of_jobs(bb_cfg()))

    with local.cwd(feature_perf_source):
        verify_binaries(project)


def _do_feature_perf_cs_collection_recompile(project: VProject) -> None:
    feature_perf_source = local.path(project.source_of(project.primary_source))

    with local.cwd(feature_perf_source / "build"):
        bb.watch(make)("-j", get_number_of_jobs(bb_cfg()))


class FeaturePerfCSCollection(VProject):
    """Test project for feature performance case studies."""

    NAME = 'FeaturePerfCSCollection'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="FeaturePerfCSCollection",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("FeaturePerfCSCollection")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("FeaturePerfCSCollection") /
                RSBinary("SingleLocalSimple"),
                label="SLS-no-input"
            ),
            Command(
                SourceRoot("FeaturePerfCSCollection") /
                RSBinary("MultiSharedMultipleRegions"),
                label="MSMR-no-input"
            ),
            Command(
                SourceRoot("FeaturePerfCSCollection") /
                RSBinary("SimpleFeatureInteraction"),
                "--enc",
                "--compress",
                label="SFI-enc-compress"
            )
        ],
        WorkloadSet(WorkloadCategory.MEDIUM): [
            Command(
                SourceRoot("FeaturePerfCSCollection") /
                RSBinary("SimpleBusyLoop"),
                "--iterations",
                str(10**7),
                "--count_to",
                str(5 * 10**3),
                label="SBL-iterations-10M-count-to-5K"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(FeaturePerfCSCollection.NAME)
        )

        binary_map.specify_binary(
            "build/bin/SingleLocalSimple", BinaryType.EXECUTABLE
        )
        binary_map.specify_binary(
            "build/bin/SingleLocalMultipleRegions",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("162db88346", "master")
        )
        binary_map.specify_binary(
            "build/bin/SimpleBusyLoop",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "c77bca4c6888970fb721069c82455137943ccf49", "master"
            )
        )
        binary_map.specify_binary(
            "build/bin/SimpleFeatureInteraction",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "c051e44a973ee31b3baa571407694467a513ba68", "master"
            )
        )
        binary_map.specify_binary(
            "build/bin/MultiSharedMultipleRegions",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "c051e44a973ee31b3baa571407694467a513ba68", "master"
            )
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(self, "FPCSC_ENABLE_SRC")

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthSAFieldSensitivity(VProject):
    """Synthetic case-study project for testing field sensitivity."""

    NAME = 'SynthSAFieldSensitivity'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthSAFieldSensitivity",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthSAFieldSensitivity")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthSAFieldSensitivity") / RSBinary("FieldSense"),
                label="FieldSense-no-input"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthSAFieldSensitivity.NAME)
        )

        binary_map.specify_binary(
            "build/bin/FieldSense",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("0a9216d769", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHSAFIELDSENSITIVITY"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthSAFlowSensitivity(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthSAFlowSensitivity'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthSAFlowSensitivity",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthSAFlowSensitivity")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthSAFlowSensitivity") / RSBinary("FlowSense"),
                label="FlowSense-no-input"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthSAFlowSensitivity.NAME)
        )

        binary_map.specify_binary(
            "build/bin/FlowSense",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("0a9216d769", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHSAFLOWSENSITIVITY"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthSAContextSensitivity(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthSAContextSensitivity'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthSAContextSensitivity",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator(
                "SynthSAContextSensitivity"
            )
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthSAContextSensitivity") /
                RSBinary("ContextSense"),
                label="ContextSense-no-input"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthSAContextSensitivity.NAME)
        )

        binary_map.specify_binary(
            "build/bin/ContextSense",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("0a9216d769", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHSACONTEXTSENSITIVITY"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthSAInterProcedural(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthSAInterProcedural'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthSAInterProcedural",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthSAInterProcedural")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthSAInterProcedural") /
                RSBinary("InterProcedural"),
                label="ContextSense-no-input"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthSAInterProcedural.NAME)
        )

        binary_map.specify_binary(
            "build/bin/InterProcedural",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("0a9216d769", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHSAINTERPROCEDURAL"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthIPRuntime(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthIPRuntime'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthIPRuntime",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthIPRuntime")
        ),
        FeatureSource(),
        HTTPMultiple(
            local="geo-maps",
            remote={
                "1.0":
                    "https://github.com/simonepri/geo-maps/releases/"
                    "download/v0.6.0"
            },
            files=["countries-land-1km.geo.json", "countries-land-1m.geo.json"]
        )
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.SMALL): [
            VCommand(
                SourceRoot("SynthIPRuntime") / RSBinary("Runtime"),
                ConfigParams("-c"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1km.geo.json.compressed"
                ],
                requires_all_args={"-c"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json.compressed"
            )
        ],
        WorkloadSet(WorkloadCategory.MEDIUM): [
            VCommand(
                SourceRoot("SynthIPRuntime") / RSBinary("Runtime"),
                ConfigParams("-c"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1m.geo.json.compressed"
                ],
                requires_all_args={"-c"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json.compressed"
            )
        ],
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        return RevisionBinaryMap(
            get_local_project_git_path(SynthIPRuntime.NAME)
        ).specify_binary(
            "build/bin/Runtime",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("4151c42ffe", "master")
        )[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHIPRUNTIME"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthIPTemplate(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthIPTemplate'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthIPTemplate",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthIPTemplate")
        ),
        FeatureSource(),
        HTTPMultiple(
            local="geo-maps",
            remote={
                "1.0":
                    "https://github.com/simonepri/geo-maps/releases/"
                    "download/v0.6.0"
            },
            files=["countries-land-1km.geo.json", "countries-land-1m.geo.json"]
        )
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.SMALL): [
            VCommand(
                SourceRoot("SynthIPTemplate") / RSBinary("Template"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1km.geo.json.compressed"
                ],
                requires_all_patch={"Compress"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json.compressed"
            )
        ],
        WorkloadSet(WorkloadCategory.MEDIUM): [
            VCommand(
                SourceRoot("SynthIPTemplate") / RSBinary("Template"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1m.geo.json.compressed"
                ],
                requires_all_patch={"Compress"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json.compressed"
            )
        ],
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        return RevisionBinaryMap(
            get_local_project_git_path(SynthIPTemplate.NAME)
        ).specify_binary(
            "build/bin/Template",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("4151c42ffe", "master")
        )[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHIPTEMPLATE"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthIPTemplate2(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthIPTemplate2'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthIPTemplate2",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthIPTemplate2")
        ),
        FeatureSource(),
        HTTPMultiple(
            local="geo-maps",
            remote={
                "1.0":
                    "https://github.com/simonepri/geo-maps/releases/"
                    "download/v0.6.0"
            },
            files=["countries-land-1km.geo.json", "countries-land-1m.geo.json"]
        )
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.SMALL): [
            VCommand(
                SourceRoot("SynthIPTemplate2") / RSBinary("Template2"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1km.geo.json.compressed"
                ],
                requires_all_patch={"Compress"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json.compressed"
            )
        ],
        WorkloadSet(WorkloadCategory.MEDIUM): [
            VCommand(
                SourceRoot("SynthIPTemplate2") / RSBinary("Template2"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1m.geo.json.compressed"
                ],
                requires_all_patch={"Compress"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json.compressed"
            )
        ],
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        return RevisionBinaryMap(
            get_local_project_git_path(SynthIPTemplate2.NAME)
        ).specify_binary(
            "build/bin/Template2",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("4151c42ffe", "master")
        )[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHIPTEMPLATE2"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthIPCombined(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthIPCombined'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthIPCombined",
            refspec="origin/HEAD",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthIPCombined")
        ),
        FeatureSource(),
        HTTPMultiple(
            local="geo-maps",
            remote={
                "1.0":
                    "https://github.com/simonepri/geo-maps/releases/"
                    "download/v0.6.0"
            },
            files=["countries-land-1km.geo.json", "countries-land-1m.geo.json"]
        )
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.SMALL): [
            VCommand(
                SourceRoot("SynthIPCombined") / RSBinary("Combined"),
                ConfigParams("-c"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1km.geo.json.compressed"
                ],
                requires_all_args={"-c"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1km.geo.json.compressed"
            )
        ],
        WorkloadSet(WorkloadCategory.MEDIUM): [
            VCommand(
                SourceRoot("SynthIPCombined") / RSBinary("Combined"),
                ConfigParams("-c"),
                label="countries-land-1km",
                creates=[
                    SourceRoot("geo-maps") /
                    "countries-land-1m.geo.json.compressed"
                ],
                requires_all_args={"-c"},
                redirect_stdin=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json",
                redirect_stdout=SourceRoot("geo-maps") /
                "countries-land-1m.geo.json.compressed"
            )
        ],
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        return RevisionBinaryMap(
            get_local_project_git_path(SynthIPCombined.NAME)
        ).specify_binary(
            "build/bin/Combined",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("4151c42ffe", "master")
        )[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHIPCOMBINED"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthCTTraitBased(VProject):
    """Synthetic case-study project for testing flow sensitivity."""

    NAME = 'SynthCTTraitBased'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthCTTraitBased",
            refspec="origin/f-SynthCompileTimeCS",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthCTTraitBased")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthCTTraitBased") / RSBinary("CT-TraitBased"),
                label="CompileTime-TraitBased"
            ),
            Command(
                SourceRoot("SynthCTTraitBased") / RSBinary("CTTraitBased"),
                label="CompileTime-TraitBased"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthCTTraitBased.NAME)
        )

        binary_map.specify_binary(
            "build/bin/CT-TraitBased",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("5c2c0535b5", "master")
        )

        binary_map.specify_binary(
            "build/bin/CTTraitBased",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("a4a133a186", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHCTTRAITBASED"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthCTPolicies(VProject):
    """Synthetic case-study project for compile time variability using
    policies."""

    NAME = 'SynthCTPolicies'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local="SynthCTPolicies",
            refspec="origin/f-SynthCompileTimeCS",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator("SynthCTPolicies")
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot("SynthCTPolicies") / RSBinary("CT-Policies"),
                label="CompileTime-Policies"
            ),
            Command(
                SourceRoot("SynthCTPolicies") / RSBinary("CTPolicies"),
                label="CompileTime-Policies"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthCTPolicies.NAME)
        )

        binary_map.specify_binary(
            "build/bin/CT-Policies",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "0768d712a2aa9b7bb3c414b742930a5e8d9ef3a7", "master"
            )
        )

        binary_map.specify_binary(
            "build/bin/CT-Policies",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("a4a133a186", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHCTPOLICIES"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthCTCRTP(VProject):
    """Synthetic case-study project for compile time variability using CRTP."""

    NAME = 'SynthCTCRTP'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local=NAME,
            refspec="origin/f-SynthCompileTimeCS",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator(NAME)
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot(NAME) / RSBinary("CT-CRTP"),
                label="CompileTime-CRTP"
            ),
            Command(
                SourceRoot(NAME) / RSBinary("CTCRTP"), label="CompileTime-CRTP"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthCTCRTP.NAME)
        )

        binary_map.specify_binary(
            "build/bin/CT-CRTP",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "8c976a890eef105d22defbf28f8a5430abec2131", "master"
            )
        )

        binary_map.specify_binary(
            "build/bin/CTCRTP",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("a4a133a186", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHCTCRTP"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)


class SynthCTTemplateSpecialization(VProject):
    """Synthetic case-study project for compile time variability using template
    specialization."""

    NAME = 'SynthCTTemplateSpecialization'
    GROUP = 'perf_tests'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-sic/FeaturePerfCSCollection.git",
            local=NAME,
            refspec="origin/f-SynthCompileTimeCS",
            limit=None,
            shallow=False,
            version_filter=project_filter_generator(NAME)
        ),
        FeatureSource()
    ]

    WORKLOADS = {
        WorkloadSet(WorkloadCategory.EXAMPLE): [
            Command(
                SourceRoot(NAME) / RSBinary("CT-TemplateSpecialization"),
                label="CompileTime-Template-Specialization"
            ),
            Command(
                SourceRoot(NAME) / RSBinary("CTTemplateSpecialization"),
                label="CompileTime-Template-Specialization"
            )
        ]
    }

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash  # pylint: disable=W0613
    ) -> tp.List[ProjectBinaryWrapper]:
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(SynthCTTemplateSpecialization.NAME)
        )

        binary_map.specify_binary(
            "build/bin/CT-TemplateSpecialization",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange(
                "81ddd858bfc3507367453c3c3ef7a1f44bb20861", "master"
            )
        )

        binary_map.specify_binary(
            "build/bin/CTTemplateSpecialization",
            BinaryType.EXECUTABLE,
            only_valid_in=RevisionRange("a4a133a186", "master")
        )

        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        _do_feature_perf_cs_collection_compile(
            self, "FPCSC_ENABLE_PROJECT_SYNTHCTSPECIALIZATION"
        )

    def recompile(self) -> None:
        """Recompile the project."""
        _do_feature_perf_cs_collection_recompile(self)
