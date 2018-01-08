
#include "usvfs_basic_test.h"

const char* usvfs_basic_test::scenario_name()
{
  return SCENARIO_NAME;
}

bool usvfs_basic_test::scenario_run()
{
  // Note: For regression purposes we don't really need to verify the results of most our operations
  // as the usvfs_test_base postmortem_check will verify the final state.
  // We still also verify the results here because:
  // A. In some cases a later step may change the results.
  // B. It is easier to understand and maintain the test when the important checks are together with
  //    their related operations.
  // C. For open issues the verifications here serve as a "documentation" of the issue (i.e. not having
  //    proper copy_on_write, etc.).

  ops_list(LR"(.)", true, true);

  // test proper path creation under overwrite when a virtualized folder is written to:

  verify_source_existance(LR"(overwrite\mfolder1)", false);
  verify_source_existance(LR"(overwrite\mfolder2)", false);
  verify_source_existance(LR"(overwrite\mfolder3)", false);
  verify_source_existance(LR"(overwrite\mfolder4)", false);

  ops_overwrite(LR"(mfolder1\fail\epic\fail\newfile1.txt)", R"(newfile1.txt nonrecursive overwrite should fail)", false, false);
  verify_source_existance(LR"(overwrite\mfolder1)", false);
  ops_overwrite(LR"(mfolder1\fail\newfile1.txt)", R"(newfile1.txt nonrecursive overwrite should fail)", false, false);
  verify_source_existance(LR"(overwrite\mfolder1)", false);
  ops_overwrite(LR"(mfolder1\newfile1.txt)", R"(newfile1.txt nonrecursive overwrite)", false);
  ops_read(LR"(mfolder1\newfile1.txt)");
  verify_source_contents(LR"(overwrite\mfolder1\newfile1.txt)", R"(newfile1.txt nonrecursive overwrite)");
  // repeat mfolder1\fail test as that folder now exists in overwrite and that changes things
  ops_overwrite(LR"(mfolder1\fail\newfile1.txt)", R"(newfile1.txt nonrecursive overwrite should fail)", false, false);

  ops_overwrite(LR"(mfolder2\newfile2.txt)", R"(newfile2.txt recursive overwrite)", true);
  ops_read(LR"(mfolder2\newfile2.txt)");
  verify_source_contents(LR"(overwrite\mfolder2\newfile2.txt)", R"(newfile2.txt recursive overwrite)");
  ops_overwrite(LR"(mfolder2\newfile2.txt\fail)", R"(newfile2.txt is a file so folder creation should fail)", true, false);
  verify_source_contents(LR"(overwrite\mfolder2\newfile2.txt)", R"(newfile2.txt recursive overwrite)");
  ops_overwrite(LR"(mfolder2\mfile.txt\fail)", R"(mfile.txt is a file so folder creation should fail)", true, false);
  verify_source_existance(LR"(overwrite\mfolder2\mfile.txt)", false);

  ops_overwrite(LR"(mfolder3\newfolder3\newfile3.txt)", R"(newfile3.txt recursive overwrite)", true);
  ops_read(LR"(mfolder3\newfolder3\newfile3.txt)");
  verify_source_contents(LR"(overwrite\mfolder3\newfolder3\newfile3.txt)", R"(newfile3.txt recursive overwrite)");
  // repeat mfolder3\newfolder3 test as that folder now exists in overwrite and that changes things
  ops_overwrite(LR"(mfolder3\newfolder3\newfile3e.txt)", R"(newfile3e.txt recursive overwrite)", true);
  ops_read(LR"(mfolder3\newfolder3\newfile3e.txt)");
  verify_source_contents(LR"(overwrite\mfolder3\newfolder3\newfile3e.txt)", R"(newfile3e.txt recursive overwrite)");

  ops_overwrite(LR"(mfolder4\newfolder4\d\e\e\p\newfile4.txt)", R"(newfile4.txt recursive overwrite)", true);
  ops_read(LR"(mfolder4\newfolder4\d\e\e\p\newfile4.txt)");
  verify_source_contents(LR"(overwrite\mfolder4\newfolder4\d\e\e\p\newfile4.txt)", R"(newfile4.txt recursive overwrite)");
  // repeat mfolder4\newfolder4\d\e\e\p test as that folder now exists in overwrite and that changes things
  ops_overwrite(LR"(mfolder4\newfolder4\d\e\e\p\newfile4e.txt)", R"(newfile4e.txt recursive overwrite)", true);
  ops_read(LR"(mfolder4\newfolder4\d\e\e\p\newfile4e.txt)");
  verify_source_contents(LR"(overwrite\mfolder4\newfolder4\d\e\e\p\newfile4e.txt)", R"(newfile4e.txt recursive overwrite)");
  // and finally verify also non-recursive works
  ops_overwrite(LR"(mfolder4\newfolder4\d\e\e\p\newfile4enr.txt)", R"(newfile4enr.txt nonrecursive overwrite)", false);
  ops_read(LR"(mfolder4\newfolder4\d\e\e\p\newfile4enr.txt)");
  verify_source_contents(LR"(overwrite\mfolder4\newfolder4\d\e\e\p\newfile4enr.txt)", R"(newfile4enr.txt nonrecursive overwrite)");
  // finally check an intermediate folder:
  ops_overwrite(LR"(mfolder4\newfolder4\d\e\epnewfile4r.txt)", R"(epnewfile4r.txt recursive overwrite)", true);
  ops_read(LR"(mfolder4\newfolder4\d\e\epnewfile4r.txt)");
  verify_source_contents(LR"(overwrite\mfolder4\newfolder4\d\e\epnewfile4r.txt)", R"(epnewfile4r.txt recursive overwrite)");
  ops_overwrite(LR"(mfolder4\newfolder4\d\e\epnewfile4.txt)", R"(epnewfile4.txt nonrecursive overwrite)", false);
  ops_read(LR"(mfolder4\newfolder4\d\e\epnewfile4.txt)");
  verify_source_contents(LR"(overwrite\mfolder4\newfolder4\d\e\epnewfile4.txt)", R"(epnewfile4.txt nonrecursive overwrite)");

  // test copy on write/delete against source "mod":

  {
    const auto& old_contents = source_contents(LR"(mod4\mfolder4\mfileoverwrite.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfileoverwrite.txt)", old_contents.c_str());
    ops_overwrite(LR"(mfolder4\mfileoverwrite.txt)", R"(mfolder4\mfileoverwrite.txt overwrite)", false);
    ops_read(LR"(mfolder4\mfileoverwrite.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfileoverwrite.txt)", old_contents.c_str());
    verify_source_contents(LR"(overwrite\mfolder4\mfileoverwrite.txt)", R"(mfolder4\mfileoverwrite.txt overwrite)");
  }

  {
    const auto& old_contents = source_contents(LR"(mod4\mfolder4\mfilerewrite.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfilerewrite.txt)", old_contents.c_str());
    ops_rewrite(LR"(mfolder4\mfilerewrite.txt)", R"(mfolder4\mfilerewrite.txt rewrite)");
    ops_read(LR"(mfolder4\mfilerewrite.txt)");
    verify_source_contents(LR"(overwrite\mfolder4\mfilerewrite.txt)", R"(mfolder4\mfilerewrite.txt rewrite)");
    if (auto copy_on_readwrite_implemented = false)
      verify_source_contents(LR"(mod4\mfolder4\mfilerewrite.txt)", old_contents.c_str());
    else
      verify_source_contents(LR"(mod4\mfolder4\mfilerewrite.txt)", R"(mfolder4\mfilerewrite.txt rewrite)");
  }

  {
    const auto& old_contents = source_contents(LR"(mod4\mfolder4\mfilemoveover.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfilemoveover.txt)", old_contents.c_str());
    ops_overwrite(LR"(mfolder4\temp_mfilemoveover.txt)", R"(mfolder4\mfilemoveover.txt overwrite)", false);
    verify_source_contents(LR"(overwrite\mfolder4\temp_mfilemoveover.txt)", R"(mfolder4\mfilemoveover.txt overwrite)");
    ops_rename(LR"(mfolder4\temp_mfilemoveover.txt)", LR"(mfolder4\mfilemoveover.txt)", true);
    ops_read(LR"(mfolder4\mfilemoveover.txt)");
    verify_source_existance(LR"(overwrite\mfolder4\temp_mfilemoveover.txt)", false);
    verify_source_contents(LR"(mod4\mfolder4\mfilemoveover.txt)", old_contents.c_str());
    verify_source_contents(LR"(overwrite\mfolder4\mfilemoveover.txt)", R"(mfolder4\mfilemoveover.txt overwrite)");
  }

  {
    const auto& old_contents = source_contents(LR"(mod4\mfolder4\mfiledeletewrite.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfiledeletewrite.txt)", old_contents.c_str());
    ops_delete(LR"(mfolder4\mfiledeletewrite.txt)");
    ops_overwrite(LR"(mfolder4\mfiledeletewrite.txt)", R"(mfolder4\mfiledeletewrite.txt overwrite)", false);
    ops_read(LR"(mfolder4\mfiledeletewrite.txt)");
    verify_source_contents(LR"(overwrite\mfolder4\mfiledeletewrite.txt)", R"(mfolder4\mfiledeletewrite.txt overwrite)");
    if (auto proper_delete_implemented = false)
      verify_source_contents(LR"(mod4\mfolder4\mfiledeletewrite.txt)", old_contents.c_str());
    else
      verify_source_existance(LR"(mod4\mfolder4\mfiledeletewrite.txt)", false);
  }

  {
    const auto& old_contents = source_contents(LR"(mod4\mfolder4\mfiledeletemove.txt)");
    verify_source_contents(LR"(mod4\mfolder4\mfiledeletemove.txt)", old_contents.c_str());
    ops_delete(LR"(mfolder4\mfiledeletemove.txt)");
    ops_overwrite(LR"(mfolder4\temp_mfiledeletemove.txt)", R"(mfolder4\mfiledeletemove.txt overwrite)", false);
    verify_source_contents(LR"(overwrite\mfolder4\temp_mfiledeletemove.txt)", R"(mfolder4\mfiledeletemove.txt overwrite)");
    ops_rename(LR"(mfolder4\temp_mfiledeletemove.txt)", LR"(mfolder4\mfiledeletemove.txt)", false);
    ops_read(LR"(mfolder4\mfiledeletemove.txt)");
    verify_source_existance(LR"(overwrite\mfolder4\temp_mfiledeletemove.txt)", false);
    verify_source_contents(LR"(overwrite\mfolder4\mfiledeletemove.txt)", R"(mfolder4\mfiledeletemove.txt overwrite)");
    if (auto proper_delete_implemented = false)
      verify_source_contents(LR"(mod4\mfolder4\mfiledeletemove.txt)", old_contents.c_str());
    else
      verify_source_existance(LR"(mod4\mfolder4\mfiledeletemove.txt)", false);
  }

  // test copy on write/delete/move against original mount files:

  {
    const auto& old_contents = mount_contents(LR"(rfolder\rfilerewrite.txt)");
    ops_rewrite(LR"(rfolder\rfilerewrite.txt)", R"(rfolder\rfilerewrite.txt rewrite)");
    ops_read(LR"(rfolder\rfilerewrite.txt)");
    verify_source_contents(LR"(overwrite\rfolder\rfilerewrite.txt)", R"(rfolder\rfilerewrite.txt rewrite)");
    if (auto copy_on_readwrite_implemented = false)
      verify_mount_contents(LR"(rfolder\rfilerewrite.txt)", old_contents.c_str());
    else if (auto copy_on_speculative_write_implemeted = true)
      verify_mount_contents(LR"(rfolder\rfilerewrite.txt)", R"(rfolder\rfilerewrite.txt rewrite)");
  }
  ops_overwrite(LR"(rfolder\rfilerewrite.txt\fail)", R"(rfilerewrite.txt is a file so folder creation should fail)", true, false);
  verify_mount_existance(LR"(rfolder\rfilerewrite.txt)"); // verifies its a file and not a directory
  verify_source_existance(LR"(overwrite\rfolder\rfilerewrite.txt)"); // verifies its a file and not a directory
  ops_overwrite(LR"(rfolder\rfile0.txt\fail)", R"(rfile0.txt is a file so folder creation should fail)", true, false);
  verify_mount_existance(LR"(rfolder\rfile0.txt)"); // verifies its a file and not a directory

  {
    const auto& old_contents = mount_contents(LR"(rfolder\rfiledelete.txt)");
    ops_delete(LR"(rfolder\rfiledelete.txt)");
    ops_read(LR"(rfolder\rfiledelete.txt)", false);
    if (auto proper_delete_implemented = false)
      verify_mount_contents(LR"(rfolder\rfiledelete.txt)", old_contents.c_str());
    else
      verify_mount_existance(LR"(rfolder\rfiledelete.txt)", false);
  }

  {
    const auto& old_contents = mount_contents(LR"(rfolder\rfileoldname.txt)");
    ops_rename(LR"(rfolder\rfileoldname.txt)", LR"(rfolder\rfilenewname.txt)", false, false);
    ops_read(LR"(rfolder\rfileoldname.txt)", false);
    ops_read(LR"(rfolder\rfilenewname.txt)");
    verify_source_contents(LR"(overwrite\rfolder\rfilenewname.txt)", old_contents.c_str());
    verify_mount_existance(LR"(rfolder\rfilenewname.txt)", false);
    if (auto copy_on_move_implemented = false)
      verify_mount_contents(LR"(rfolder\rfileoldname.txt)", old_contents.c_str());
    else
      verify_mount_existance(LR"(rfolder\rfileoldname.txt)", false);
  }

  ops_list(LR"(.)", true, true);

  return true;
}
