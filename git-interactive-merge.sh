#!/bin/bash
#git-interactive-merge
from=$1
to=$2
git checkout $from
git checkout -b ${from}_tmp
git rebase -i $to
if [ $? -ne 0 ];then
 echo "Git rebase failed, fix conflicts and:"
 echo "  #>./git-interactive-merge-continue.sh ${from} ${to}"
fi

git checkout $to
git pull .${from}_tmp
git branch -d ${from}_tmp
