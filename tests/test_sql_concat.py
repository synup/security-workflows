"""SQL keyword boundaries: retain injection detection without matching Slack JSON labels."""
import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from scan.checks import dangerous_code

MALICIOUS = {
 'js_select_concat': 'db.query("SELECT * FROM users WHERE id=" + uid)',
 'js_update_template': 'db.query(`UPDATE users SET name=${name} WHERE id=1`)',
 'js_insert_template': 'db.query(`INSERT INTO users(name) VALUES (${name})`)',
 'js_delete_template': 'db.query(`DELETE FROM users WHERE id=${id}`)',
 'python_format': 'db.execute("SELECT * FROM users WHERE id={}".format(uid))',
 'python_percent': 'db.execute("SELECT * FROM users WHERE id=%s" % (uid,))',
 'single_quote_concat': "db.query('SELECT * FROM users WHERE id=' + uid)",
 'lowercase': 'db.query(`update users set name=${name}`)',
 'mixed_case': 'db.query(`SeLeCt * from users where id=${id}`)',
 'comment_separator': 'db.query(`UPDATE/**/users SET name=${name}`)',
 'select_comment': 'db.query("SELECT/**/id FROM users WHERE id=" + uid)',
 'select_star_no_space': 'db.query("SELECT*FROM users WHERE id=" + uid)',
 'quoted_table': 'db.query(`UPDATE"users" SET name=${name}`)',
 'quoted_column': 'db.query(`SELECT"name" FROM users WHERE id=${id}`)',
 'bracket_table': 'db.query(`UPDATE[users] SET name=${name}`)',
 'select_parenthesis': 'db.query(`SELECT(id) FROM users WHERE name=${name}`)',
 'named_bind_no_space': 'db.query("SELECT:bound FROM users WHERE id=" + uid)',
 'anonymous_bind_no_space': 'db.query("SELECT? FROM users WHERE id=" + uid)',
 'sql_inside_slack_payload': 'post("chat.update", {text: `UPDATE users SET name=${name}`})',
 'sql_inside_message_label': 'log(`Previous update: SELECT * FROM users WHERE id=${id}`)',
}
BENIGN = {
 'cshq_superseded': 'return this.post(\'chat.update\', d, {ts: d.previous_root_ts, text: `Superseded activity · continue in <https://synup.slack.com/archives/${d.channel_id}/p${d.root_ts.replace(\'.\',\'\')}|new activity>\\nPrevious update: ${escape(previousSummary)}\\nCase remains ${escape(d.action_state)}`});',
 'slack_json': 'post("chat.update", {text: `Customer ${escape(name)} replied`})',
 'update_label': 'const text = `Previous update: ${escape(summary)}`;',
 'delete_label': 'const text = `Delete: ${escape(label)}`;',
 'method_identifier': 'client.update({text: `${summary}`})',
 'prefixed_identifier': 'const preselect = `value ${name}`;',
 'parameterized_sql': 'db.query("SELECT * FROM users WHERE id=$1", [uid])',
 'literal_sql': 'db.query("UPDATE users SET name=42")',
}

def findings(text):
 return [f for f in dangerous_code.check(Path('sample.ts'),'sample.ts',text,text.splitlines(),set()) if f.detail=='sql_concat']

class SqlConcatTests(unittest.TestCase):
 def test_genuine_sql_still_high(self):
  for name,text in MALICIOUS.items():
   with self.subTest(name=name):
    result=findings(text);self.assertTrue(result);self.assertTrue(all(f.severity=='high' for f in result))
 def test_benign_payloads_not_sql(self):
  for name,text in BENIGN.items():
   with self.subTest(name=name):self.assertEqual(findings(text),[])

if __name__=='__main__':unittest.main()
