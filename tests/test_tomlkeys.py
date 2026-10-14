import unittest

from agent_hygiene import tomlkeys


class TestTomlKeys(unittest.TestCase):
    def test_empty_file_gets_a_table(self):
        out = tomlkeys.set_value("", "features", "daemon_auto_start", False)
        self.assertEqual(out, "[features]\ndaemon_auto_start = false\n")
        self.assertIs(tomlkeys.get(out, "features", "daemon_auto_start"), False)

    def test_existing_value_is_replaced_and_everything_else_kept(self):
        text = ('# my codex config\nmodel = "o3"\n\n[features]\n# keep this comment\n'
                'web_search = true\ndaemon_auto_start = true  # default\n\n[profiles.fast]\nmodel = "mini"\n')
        out = tomlkeys.set_value(text, "features", "daemon_auto_start", False)
        self.assertIn("daemon_auto_start = false\n", out)
        self.assertNotIn("daemon_auto_start = true", out)
        for kept in ("# my codex config", 'model = "o3"', "# keep this comment", "web_search = true",
                     "[profiles.fast]", 'model = "mini"'):
            self.assertIn(kept, out)
        self.assertIs(tomlkeys.get(text, "features", "daemon_auto_start"), True)

    def test_key_added_to_existing_table(self):
        text = '[features]\nweb_search = true\n\n[tui]\ntheme = "dark"\n'
        out = tomlkeys.set_value(text, "features", "daemon_auto_start", False)
        self.assertTrue(out.startswith("[features]\ndaemon_auto_start = false\nweb_search = true\n"))
        self.assertIs(tomlkeys.get(out, "tui", "daemon_auto_start"), None)

    def test_top_level_dotted_key(self):
        text = 'model = "o3"\nfeatures.daemon_auto_start = true\n'
        self.assertIs(tomlkeys.get(text, "features", "daemon_auto_start"), True)
        out = tomlkeys.set_value(text, "features", "daemon_auto_start", False)
        self.assertEqual(out, 'model = "o3"\nfeatures.daemon_auto_start = false\n')

    def test_same_key_in_another_table_is_ignored(self):
        text = '[other]\ndaemon_auto_start = true\n'
        self.assertIsNone(tomlkeys.get(text, "features", "daemon_auto_start"))
        out = tomlkeys.set_value(text, "features", "daemon_auto_start", False)
        self.assertIn("[other]\ndaemon_auto_start = true\n", out)
        self.assertTrue(out.endswith("[features]\ndaemon_auto_start = false\n"))

    def test_inline_table_is_refused(self):
        with self.assertRaises(ValueError):
            tomlkeys.set_value("features = { daemon_auto_start = true }\n", "features", "daemon_auto_start", False)

    def test_multiline_string_is_not_parsed_as_a_header(self):
        text = 'instructions = """\n[features]\ndaemon_auto_start = true\n"""\n'
        self.assertIsNone(tomlkeys.get(text, "features", "daemon_auto_start"))
        out = tomlkeys.set_value(text, "features", "daemon_auto_start", False)
        self.assertTrue(out.startswith(text))
        self.assertTrue(out.endswith("[features]\ndaemon_auto_start = false\n"))

    def test_top_level_key_goes_before_tables(self):
        out = tomlkeys.set_value('[features]\nx = 1\n', None, "check_for_update_on_startup", False)
        self.assertEqual(out, 'check_for_update_on_startup = false\n[features]\nx = 1\n')


if __name__ == "__main__":
    unittest.main()
