"""Projects in vara-test-repos used for testing the bug provider."""
import typing as tp

import benchbuild as bb
from plumbum import local

from varats.paper.paper_config import PaperConfigSpecificGit
from varats.project.project_domain import ProjectDomains
from varats.project.project_util import (
    ProjectBinaryWrapper,
    wrap_paths_to_binaries,
    BinaryType,
)
from varats.project.varats_project import VProject
from varats.utils.git_util import ShortCommitHash

class CFI(VProject):  # type: ignore

    NAME = 'CFI'      # The name of the project
    GROUP = 'cpp_projects'  # The group this project belongs to
    DOMAIN = ProjectDomains.TEST   # The application domain of this project

    SOURCE = [
        PaperConfigSpecificGit(
            project_name="CFI",
            remote="https://github.com/sisteu56/commit-feature-interactions_test_repo.git",
            local="CFI",
            refspec="main",
            limit=None,
            shallow=False
        )
    ]

    test_files = [
        "main.cpp", "helper.cpp"
    ]

    @property
    def binaries(self) -> tp.List[ProjectBinaryWrapper]:
        """Return a list of binaries generated by the project."""
        return wrap_paths_to_binaries(binaries=[("main", BinaryType.EXECUTABLE),("helper", BinaryType.EXECUTABLE)])

    def run_tests(self) -> None:
        """ This function defines tests and benchmarks for the project. """
        pass

    def compile(self) -> None:
        """ Contains instructions on how to build the project. """
        source = local.path(self.source_of_primary)
        clang = bb.compiler.cxx(self)
        with local.cwd(source):
            for test_file in self.test_files:
                bb.watch(clang)(test_file, "-o", test_file.replace('.cpp', ''))
