"""Compile a collection of representing examples for the taint analysis."""
import typing as tp

import benchbuild as bb
from plumbum import local

from varats.project.project_domain import ProjectDomains
from varats.project.project_util import (
    ProjectBinaryWrapper,
    BinaryType,
    get_local_project_git_path,
)
from varats.project.varats_project import VProject
from varats.utils.git_util import RevisionBinaryMap, ShortCommitHash


class TaintTests(VProject):
    """
    Taint tests:

    Different small test files for taint propagation
    """

    NAME = 'taint-tests'
    GROUP = 'test_projects'
    DOMAIN = ProjectDomains.TEST

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-passau/vara-perf-tests.git",
            local="taint-tests",
            limit=1,
            refspec="origin/f-taintTests"
        )
    ]

    CPP_FILES = [
        "arrayTaintPropagation.cpp", "byValueArgPassing.cpp",
        "coercedArgPassing.cpp", "coercedReturnValuePassing.cpp",
        "controlFlowDependency.cpp", "operatorTaintPropagation.cpp",
        "pointerTaintPropagation1.cpp", "pointerTaintPropagation2.cpp",
        "pointerTaintPropagation3.cpp", "regularArgPassing.cpp",
        "regularReturnValuePassing.cpp", "returnValueMapping.cpp",
        "switchFallthrough.cpp", "unionTaintPropagation.cpp",
        "variableLengthArgForwarding.cpp", "variableLengthArgPassing.cpp"
    ]

    @staticmethod
    def binaries_for_revision(
        revision: ShortCommitHash
    ) -> tp.List[ProjectBinaryWrapper]:
        """Return a list of binaries generated by the project."""
        binary_map = RevisionBinaryMap(
            get_local_project_git_path(TaintTests.NAME)
        )
        for file_name in TaintTests.CPP_FILES:
            binary_map.specify_binary(
                file_name.replace('.cpp', ''), BinaryType.EXECUTABLE
            )
        return binary_map[revision]

    def run_tests(self) -> None:
        pass

    def compile(self) -> None:
        """Compile the project."""
        source = local.path(self.source_of_primary)

        clang = bb.compiler.cxx(self)
        with local.cwd(source):
            for file in self.CPP_FILES:
                bb.watch(clang)(
                    f"{self.NAME}/{file}", "-o", file.replace('.cpp', '')
                )


class TestTaintTests(bb.Project):  # type: ignore
    """
    Used as a test project to test if we can interact with this project.

    Different small test files for taint propagation
    """

    NAME = 'test-taint-tests'
    GROUP = 'test_projects'
    DOMAIN = 'testing'

    SOURCE = [
        bb.source.Git(
            remote="https://github.com/se-passau/vara-perf-tests.git",
            local="test-taint-tests",
            limit=1,
            shallow=False,
            refspec="origin/test-refspec"
        )
    ]

    @property
    def binaries(self) -> tp.List[ProjectBinaryWrapper]:
        """Return a list of binaries generated by the project."""
        return []

    def run_tests(self) -> None:
        """Empty run tests."""

    def compile(self) -> None:
        """Empty compile."""
