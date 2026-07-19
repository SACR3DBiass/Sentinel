import sys

with open('settings_page.html', 'r', encoding='utf-8') as f:
    new_content = f.read()

with open('app.py', 'r', encoding='utf-8') as f:
    app_content = f.read()

start_marker = 'SETTINGS_PAGE = """<!DOCTYPE html>'
end_marker = '# ============================================================================\n# MARKETING PAGE'

start_idx = app_content.find(start_marker)
end_idx = app_content.find(end_marker, start_idx)

if start_idx == -1 or end_idx == -1:
    print("ERROR: Could not find markers. start=%d, end=%d" % (start_idx, end_idx))
    sys.exit(1)

new_settings = 'SETTINGS_PAGE = """' + new_content + '"""\n\n' + end_marker

app_content = app_content[:start_idx] + new_settings + app_content[end_idx + len(end_marker):]

with open('app.py', 'w', encoding='utf-8') as f:
    f.write(app_content)

print("SUCCESS: Replaced SETTINGS_PAGE (%d bytes new HTML)" % len(new_content))
print("New app.py size: %d bytes" % len(app_content))
