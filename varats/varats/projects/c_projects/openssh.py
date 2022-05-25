"""Project file for openssh."""
# import typing as tp
#
# import benchbuild as bb
# from benchbuild.project import Project
# from benchbuild.utils.cmd import make, source, autoreconf
# from benchbuild.utils.compiler import cc
# from benchbuild.utils.download import with_git
# from benchbuild.utils.settings import get_number_of_jobs
# from plumbum import local
#
# from varats.paper_mgmt.paper_config import project_filter_generator
# from varats.project.project_util import (
#     wrap_paths_to_binaries,
#     ProjectBinaryWrapper,
# )
# from varats.provider.cve.cve_provider import CVEProviderHook
#
#
# class OpenSSH(Project, CVEProviderHook):  # type: ignore
#     """An implementation of the SSH protocol (fetched by Git)"""
#
#     NAME = 'openssh-portable'
#     GROUP = 'c_projects'
#     DOMAIN = 'security'
#     VERSION = 'HEAD'
#
#     #SRC_FILE = NAME + "-{0}".format(VERSION)
#     SOURCE = bb.source.Git(
#         remote="https://github.com/openssh/openssh-portable.git",
#         refspec="HEAD",
#         version_filter=project_filter_generator("openssh-portable"),
#         local="openssh-portable"
#     )
#
#     @property
#     def binaries(self) -> tp.List[ProjectBinaryWrapper]:
#         """Return a list of binaries generated by the project."""
#         # TODO
#         return wrap_paths_to_binaries(["openssh-portable"])
#
#     def run_tests(self) -> None:
#         pass
#
#     def compile(self) -> None:
#         # self.download()
#         path = local.path(self.source_of(self.primary_source))
#
#         clang = bb.compiler.cc(self)
#         with local.cwd(path):
#             with local.env(CC=str(clang)):
#                 # run(autoreconf)
#                 bb.watch(autoreconf)()
#                 # run(local["./configure"])
#                 bb.watch(local["./configure"])()
#             #run(make["-j", get_number_of_jobs(bb_cfg())])
#             bb.watch(make)("-j", get_number_of_jobs(bb_cfg()))
#
#     @classmethod
#     def get_cve_product_info(cls) -> tp.List[tp.Tuple[str, str]]:
#         return [("openssh-portable", "openssh")]
