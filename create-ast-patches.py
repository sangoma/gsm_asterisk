#!/usr/bin/env python
# vim: tabstop=4 softtabstop=4 shiftwidth=4 textwidth=80 smarttab expandtab
"""
* Copyright (C) 2011  Sangoma Technologies Corp.
* All Rights Reserved.
*
* Author(s)
* Moises Silva <moy@sangoma.com>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU Lesser General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Contributors:
*
"""

"""
Generate Asterisk patches from git tags and branches 
This script must be run from a gsm_asterisk repository
"""

import re
import subprocess 

p1 = subprocess.Popen(['git', 'tag'], stdout=subprocess.PIPE)
p2 = subprocess.Popen(['grep', 'asterisk'], stdin=p1.stdout, stdout=subprocess.PIPE)
p1.stdout.close()
output = p2.communicate()[0]

output = output.strip()
tags = output.split("\n")

regex = re.compile('asterisk-([0-9]+\.[0-9]+)\.?([0-9.]+)?.unpatched')
for tag in tags:
	m = regex.findall(tag)
	if len(m) == 0:
		print "Skipping tag " + tag
		continue
	majver = m[0][0]
	tagver = majver
	if len(m[0]) > 1:
		tagver += "." + m[0][1]
	branch = "asterisk-" + majver
	rc = subprocess.call(['git', 'checkout', branch])
	if rc is not 0:
		origbranch = "origin/" + branch
		rc = subprocess.call(['git', 'checkout', '-b', branch, origbranch])
		if rc is not 0:
			print "Failed to checkout branch " + origbranch
			continue

	patch = "asterisk-" + tagver + ".patch"
	pf = open(patch, "w")
	if pf is None:
		print "Failed to create patch file " + patch
		sys.exit(1)

	diff = "git diff " + tag + " HEAD"
	p = subprocess.Popen(diff, shell=True, stdout=pf)
	rc = p.wait()
	if rc is not 0:
		print "Failed to create diff between tag %s and branch %s" % (tag, branch)
		sys.exit(1)
	pf.close()
	print "Created patch " + patch


