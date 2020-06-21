#!/bin/bash


        find -name 2008.txt | xargs grep -i -c "aa08-\|ta08" | awk '{a+=$1} END{print "2008  " a}' 
        find -name 2009.txt | xargs grep -i -c "aa09-\|ta09" | awk '{a+=$1} END{print "2009  " a}' 
        find -name 2010.txt | xargs grep -i -c "aa10-\|ta10" | awk '{a+=$1} END{print "2010  " a}' 
        find -name 2011.txt | xargs grep -i -c "aa11-\|ta11" | awk '{a+=$1} END{print "2011  " a}' 
        find -name 2012.txt | xargs grep -i -c "aa12-\|ta12" | awk '{a+=$1} END{print "2012  " a}' 
        find -name 2013.txt | xargs grep -i -c "aa13-\|ta13" | awk '{a+=$1} END{print "2013  " a}' 
        find -name 2014.txt | xargs grep -i -c "aa14-\|ta14" | awk '{a+=$1} END{print "2014  " a}' 
        find -name 2015.txt | xargs grep -i -c "aa15-\|ta15" | awk '{a+=$1} END{print "2015  " a}' 
        find -name 2016.txt | xargs grep -i -c "aa16-\|ta16" | awk '{a+=$1} END{print "2016  " a}' 
        find -name 2017.txt | xargs grep -i -c "aa17-\|ta17" | awk '{a+=$1} END{print "2017  " a}' 
        find -name 2018.txt | xargs grep -i -c "aa18-\|ta18" | awk '{a+=$1} END{print "2018  " a}' 
        find -name 2019.txt | xargs grep -i -c "aa19-\|ta19" | awk '{a+=$1} END{print "2019  " a}' 
        find -name 2020.txt | xargs grep -i -c "aa20-\|ta20" | awk '{a+=$1} END{print "2020  " a}'




