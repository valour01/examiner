#!/usr/bin/env python3

'''
Unpack ARM instruction XML files extracting the encoding information
and ASL code within it.
'''
import time
import json
import argparse
import glob
import json
import os
import re
import string
import random
import sys
import xml.etree.cElementTree as ET
from collections import defaultdict
from itertools import takewhile
from z3 import *
from functools import reduce

include_regex = None
exclude_regex = None

all_encoding = 0
all_insts = 0
all_constraint = 0
all_valid_constraint = 0
all_solved_constraint = 0
fail_solved_constraint = []

########################################################################
# Tag file support
########################################################################

def find(s, ch):
    return [i for i, ltr in enumerate(s) if ltr == ch]


def BitCount(b):
    n = b.size()
    bits = [ Extract(i, i, b) for i in range(n) ]
    bvs  = [ Concat(BitVecVal(0, n - 1), b) for b in bits ]
    nb   = reduce(lambda a, b: a + b, bvs)
    return nb


def removeBrackets(string):
    if string.startswith("(") and string.endswith(")"):
        string = string[1:-1]
    return string

def hasValueOnIndex(value,index,fuzz_list):
    for fuzz_item in fuzz_list:
        if fuzz_item[index] == value:
            return True 
    return False

def hasUIntValue(value,fuzz_list):
    for fuzz_item in fuzz_list:
        if bin(int(value))[2:] == fuzz_list:
            return True 
    return False




def removeConditionInStatement(statement,conditions):
    for c in conditions:
        if c in statement:
            statement = statement.replace(c,"")
    return statement

def update_fuzz_field(fuzz_field,new_fuzz_field):
    for name in fuzz_field:
        fuzz_field[name]["fuzz_list"] = list(set(fuzz_field[name]["fuzz_list"]) | set(new_fuzz_field[name]["fuzz_list"]))
    return fuzz_field

def split_by(lists,mark):
    results = []
    for l in lists:
        for l_s in l.split(mark):
            if l_s !="":
                results.append(l_s)
    return results
        

def extractVariables(statement):
    results = []
    variables = split_by([statement]," ")
    variables = split_by(variables,"+")
    variables = split_by(variables,"-")
    variables = split_by(variables,":")
    for v in variables:
        if v.startswith("'") and v.endswith("'"):
            v = v[1:-1]
        try: 
            i_v = int(v)
        except:
            if v != "+" and v !="-" and "=" not in v and ">" not in v and "<" not in v:
                results.append(v)
    return results


def removeUInt(name):
    results = re.findall(r'UInt\((\w+)\)',name)
    if len(results) == 0:
        return name
    else:
        return name.replace("UInt("+results[0]+")",results[0])


def isConstant(value):
    constant = re.findall(r'[0-9x]+',value)
    if len(constant) == 0:
        return False
    return True

def isUInt(name):
    results = re.findall(r'UInt\((\w+)\)',name)
    if len(results) == 0:
        return False
    else:
        return results[0]

def getField(name,fields):
    for field in fields:
        if field.name == name:
            return field 
    return None
    




def getOneValueWithName(name,fuzz_field,alias):
    if name in fuzz_field:
        return fuzz_field[name]["fuzz_list"][0]
    elif name in alias:
        for c in alias[name]:
            if c in fuzz_field:
                return fuzz_field[c]["fuzz_list"][0]
            UInt = isUInt(c)
            if UInt in fuzz_field:
                return fuzz_field[UInt]["fuzz_list"][0]
    return None


def addValueToFuzzField(condition_name,condition_value,fuzz_field,alias):
    # we need to check the type of the condition_name
    # the field name
    # Rn

    # Check  if the condition value is constant
    # if d == n
    # convert n to one of the value in its fuzz_list

    if not isConstant(condition_value):
        condition_value = getOneValueWithName(condition_value,fuzz_field,alias)
    
    if condition_value == None:
        return fuzz_field
    
    # In the fuzz_list
    if condition_name in fuzz_field:
        if condition_value not in fuzz_field[condition_name]["fuzz_list"]:
            fuzz_field[condition_name]["fuzz_list"].append(condition_value)
        if negateOneZero(condition_value) not in fuzz_field[condition_name]["fuzz_list"]:
            fuzz_field[condition_name]["fuzz_list"].append(negateOneZero(condition_value))
        return fuzz_field 
    else:
    # not in the fuzz list, but may has alias
        if condition_name in alias:
            alias_names = alias[condition_name]
            for alias_name in alias_names:
                new_fuzz_field = addValueToFuzzField(alias_name,condition_value,fuzz_field,alias)
                fuzz_field = update_fuzz_field(fuzz_field, new_fuzz_field) 
                return fuzz_field

    # the field name with index
    # Vd[0]
    isArray = re.findall(r'(\w+)\[([0-9]+)\]',condition_name)
    if len(isArray)>0:
        value_name = isArray[0][0]
        value_index = int(isArray[0][1])
        new_value = ""
        if not hasValueOnIndex(condition_value,value_index,fuzz_field[value_name]["fuzz_list"]):
            #change the first value in the list
            first_value = fuzz_field[value_name]["fuzz_list"][0]
            new_value = first_value[:value_index]+condition_value+first_value[value_index+1:]
            fuzz_field[value_name]["fuzz_list"].append(new_value)
        if negateOneZero(new_value) not in fuzz_field[value_name]["fuzz_list"]:
            fuzz_field[value_name]["fuzz_list"].append(negateOneZero(new_value))
        return fuzz_field
   
    # The field name converted to Int
    # UInt(Rd)
    UInt_name = isUInt(condition_name)
    if UInt_name:
        if not hasUIntValue(condition_value,fuzz_field[UInt_name]["fuzz_list"]):
            fuzz_field[UInt_name]["fuzz_list"].append(bin(int(condition_value))[2:])
        if negateOneZero(bin(int(condition_value))[2:]) not in fuzz_field[UInt_name]["fuzz_list"]:
            fuzz_field[UInt_name]["fuzz_list"].append(negateOneZero(bin(int(condition_value))[2:]))

        return fuzz_field

    return fuzz_field 

def extend_insts(lst):
    newlist = []
    count = 0
    for item in lst:
        if "x" not in item:
            newlist.append(item)
        else:
            count += 1
            idx = item.index("x")
            newlist.append(item[:idx] + "0" + item[idx + 1 :])
            newlist.append(item[:idx] + "1" + item[idx + 1 :])
    if count > 0:
        return extend_insts(newlist)
    else:
        return newlist




def negateOneZero(code):
    newcode = ''
    if '0' not in code and '1' not in code and 'x' not in code:
        try:
            code = bin(int(code))[2:]
        except:
            return None
    for c in code:
        if c == '0':
            newcode += '1'
        if c == '1':
            newcode += '0'
    return newcode


def handleIfStatement(code):
    conditions = []
    ifRegex = re.compile(r'if (.*?) then')
    allIfs = re.findall(ifRegex,code)
    for condition in allIfs:
        condition = condition.strip()
        if len(condition.split(" ")) == 1:
            if condition.startswith("!"):
                condition = condition[1:] + " == False"
            else:
                condition = condition + " == True"
        conditions.append(condition)
    return conditions

def handleOneCaseStatement(code):
    conditions = []
    case_variable = re.findall(r'case (.*) of',code)
    if len(case_variable) > 0:
        print(case_variable[0])
    for line in code.split('\n'):
        value = ""
        results = re.findall("when\s+\'([01x\s]+)\'",line)
        if len(results) > 0:
            value = results[0]
        elif 'when' in line:  
            value = line.split("when")[1].strip().split(" ")[0]
        if value != "":
            condition = case_variable[0]+" == "+value 
            conditions.append(condition)
    return conditions

    

def handleCaseStatement(code):
    all_conditions = []
    case_indexes = [m.start() for m in re.finditer('case', code)] 
    case_indexes.append(len(code))
    if len(case_indexes) == 2:
        #only one case in the code
        conditions = handleOneCaseStatement(code[case_indexes[0]:case_indexes[1]])
        all_conditions.extend(conditions)
    else:
        for c_s, c_e in zip(case_indexes[:-1],case_indexes[1:]):
            conditions = handleOneCaseStatement(code[c_s:c_e])
            all_conditions.extend(conditions)
    return all_conditions


def analyzeDecodeASL(code):
    results = {}
    statements = code.split(";")
    for statement in statements:
        result = analyzeOneStatement(statement.strip())
        for key in result:
            if key not in results:
                results[key] = result[key]
            else:
                results[key].extend(result[key])
    return results

def analyzeOneStatement(code):
    results = {}
    if " = " not in code:
        return results
    left_hand = code.split(" = ")[0].strip()
    #handle the left_hand 
    left_hand = left_hand.split(" ")[-1]
    #handle the right hand
    right_hand = code.split(" = ")[1].strip()
    if_statement  = re.findall(r'if (.*) then (.*) else (.*)', right_hand)
    if len(if_statement) > 0:
        then_value = if_statement[0][1]
        else_value = if_statement[0][2]
        if else_value.endswith(";"):
            else_value = else_value[:-1]
        results[left_hand] = []
        results[left_hand].append(then_value)
        results[left_hand].append(else_value)
        return results 

    results[left_hand] = [right_hand]
    return results
        
    


def splitCondition(condition):
    equal = "=="
    notEqual = "!="
    greater = ">"
    less = "<"
    greaterEqual = ">="
    lessEqual = "<="

    if equal in condition:
        return condition.split(equal)
    if notEqual in condition:
        return condition.split(notEqual)
    if greaterEqual in condition:
        return condition.split(greaterEqual)
    if lessEqual in condition:
        return condition.split(lessEqual)
    if greater in condition:
        return condition.split(greater)
    if less in condition:
        return condition.split(less)
    return [condition,'True']

def bin_x(num):
    return [bin(i)[2:].zfill(num) for i in range(2 ** num)]


special_regs_4bits = ["0000", "1111"]
special_regs_3bits = ["000"]
left_regs_4bits = [x for x in bin_x(4) if x not in special_regs_4bits]
left_regs_3bits = [x for x in bin_x(3) if x not in special_regs_3bits]


def extend_seedlist(orig_list, cases):
    new_list = []
    for orig in orig_list:
        for case in cases:
            if case == None:
                continue
            new_list.append(orig + case)
    return new_list


tags = set()
'''
Write content to a 'tag file' suppressing duplicate information
'''
def emit(f, tag, content):
    if tag not in tags: # suppress duplicate entries
        tags.add(tag)
        print('TAG:'+tag, file=f)
        print(content, file=f)


########################################################################
# Workarounds
########################################################################

# workaround: v8-A code still uses the keyword 'type' as a variable name
# change that to 'type1'
def patchTypeAsVar(x):
    return re.sub(r'([^a-zA-Z0-9_\n])type([^a-zA-Z0-9_])', r'\1type1\2', x)

########################################################################
# Classes
########################################################################


class Condition:
    '''Representation of ASL code containing the if statement'''
    def __init__(self, statement,fields,solve = False):
        self.fields = fields
        self.orig_statement = statement

        self.statement = self.parseCondition(statement)
        self.negate_statement  = ""
        self.patchAnd()
        self.patchDot()
        self.patchUInt()
        self.patchColon()
        self.patchArray()
        self.patchDIV()
        self.patchLowestBit()

        if solve:
            self.patchNegate()


    def patchAnd(self):
        if "AND" in self.statement:
            self.statement = self.statement.replace("AND","&")

    def patchRightHand(self,right_hand):
        right_hand = right_hand.replace("x","0")
        
        try:
            if right_hand.startswith("'") and right_hand.endswith("'"):
                right_hand = right_hand[1:-1]
            right_hand = str(int(right_hand.replace(" ",""),2))
        except:
            pass 
        return right_hand

    def parseCondition(self,statement):

        if " or " in statement:
            sub_statements = statement.split(" or ")
            patched_statements = []
            for sub_statement in sub_statements:
                patched_statements.append(self.parseCondition(sub_statement))
            return "Or("+", ".join(patched_statements)+")"
        if "==" in statement:
            split =  statement.split("==")
            return split[0].strip()+ " == " + self.patchRightHand(split[1].strip())
        if "!=" in statement:
            split =  statement.split("!=")
            return split[0].strip()+ " != " + self.patchRightHand(split[1].strip())
        if ">=" in statement:
            split =  statement.split(">=")
            return split[0].strip()+ " >= " + self.patchRightHand(split[1].strip())
        if "<=" in statement:
            split =  statement.split("<=")
            return split[0].strip()+ " <= " + self.patchRightHand(split[1].strip())
        if ">" in statement:
            split =  statement.split(">")
            return split[0].strip()+ " > " + self.patchRightHand(split[1].strip())
        if "<" in statement:
            split =  statement.split("<")
            return split[0].strip()+ " < " + self.patchRightHand(split[1].strip())



    def patchNegate(self):
        self.negate_statement = "Not(%s)"%self.statement
        """
        if  "==" in self.statement:
            self.negate_statement = self.statement.replace("==","!=")
            return
        if  "!=" in self.statement:
            self.negate_statement = self.statement.replace("!=","==")
            return
        if  ">=" in self.statement:
            self.negate_statement = self.statement.replace(">=","<")
            return
        if  "<=" in self.statement:
            self.negate_statement = self.statement.replace("<=",">")
            return
        if  ">" in self.statement:
            self.negate_statement = self.statement.replace(">","<=")
            return
        if  "<" in self.statement:
            self.negate_statement = self.statement.replace("<",">=")
            return
        """

    def __str__(self):
        return self.orig_statement+" Converted to: "+self.statement

    def patchDot(self):
        self.statement = self.statement.replace(".","_")

    def patchDIV(self):
        results = re.findall(r'(\w+)\sDIV\s(\w+)',self.statement)
        for result in results:
            rep = "UDiv(%s,%s)"%(result[0],result[1])
            self.statement = self.statement.replace("%s DIV %s"%(result[0],result[1]),rep)

    def patchArray(self):
        results = re.findall(r'((\w+)\[([0-9a-zA-Z]+)\])',self.statement)
        for result in results:
            try:
                value_index = int(result[2])
                rep = "ZeroExt(31,Extract( %s , %s , %s))"%(result[2],result[2],result[1])
                self.statement = self.statement.replace(result[0],rep)
            except:
                pass

    def patchLowestBit(self):
        results = re.findall(r'(LowestSetBit\((\w+)\))',self.statement)
        for result in results:
            self.statement = "Or(And(%s==16,%s),And(%s==8,%s))" % (result[1],self.statement.replace(result[0],"4"),result[1],self.statement.replace(result[0],"3"))

    def patchUInt(self):
        #print("{} is UInt or not?".format(self.statement))
        results = re.findall(r'UInt\(([\w\:\[\]]+)\)',self.statement)
        for result in results:
            self.statement = self.statement.replace("UInt(%s)"%result,result)
       
    def patchColon(self):
        #Rd[3:2]
        colons = re.findall(r'(([a-zA-Z0-9_]+)\[(\d+):(\d+)])',self.statement)
        for colon in colons:
            rep = "ZeroExt(%s,Extract(%s,%s,%s))"%(str(31-(int(colon[2])-int(colon[3]))),colon[2],colon[3],colon[1])
            #rep ="(%s >> %s) & %s"%(colon[1],colon[3],str(2**(int(colon[2])-int(colon[3])+1)-1))
            self.statement = self.statement.replace(colon[0],rep)

        # Rd:Rm 
        for result in self.statement.split(" "):
            if ":" in result:
                new_result = []
                bit_num = 0
                v_names = result.split(":")
                v_names.reverse()
                new_result.append(v_names[0])
                for v_name,v_next_name in zip(v_names[:-1],v_names[1:]):
                    v_field = getField(v_name,self.fields)
                    if v_field != None:
                        bit_num += v_field.bits
                        new_result.append(v_next_name + '*'+ str(2**int(bit_num)))
                self.statement = self.statement.replace(result,"("+" + ".join(new_result)+")")
        


    def get_constraint(self,fields):
        constraint = self.statement
                       
        return constraint
      

    def get_variables(self):
        results = []
        variables = split_by([self.statement]," ")
        variables = split_by(variables,"+")
        variables = split_by(variables,",")
        variables = split_by(variables,"-")
        variables = split_by(variables,"*")
        variables = split_by(variables,":")
        variables = split_by(variables,"&")
        variables = split_by(variables,">>")
        variables = split_by(variables,"(")
        variables = split_by(variables,")")
        for v in variables:
            if v.startswith("'") and v.endswith("'"):
                v = v[1:-1]
            if v.startswith("0b"):
                v = v[2:]
            try: 
                i_v = int(v)
            except:
                if v != "+" and v !="-" and "=" not in v and ">" not in v and "<" not in v:
                    if v == "Extract":
                        continue
                    if v == "BitCount":
                        continue
                    if v == "Or":
                        continue
                    if v == "UDiv":
                        continue
                    if v == "ZeroExt":
                        continue
                    results.append(v)
        return results





class Field:
    def __init__(self,start,end,name,structure):
        self.start = start
        self.end = end 
        self.name = name 
        self.structure = structure.replace(" ","").replace("(","").replace(")","")
        self.bits = len(self.structure)
        self.type = self.getFieldType()
        self.fuzz_list = []


    def isField(self,bits):
        if "x" not in self.structure:
            if self.structure == bits:
                return True 
        else:
            flag = True
            for i in range(len(bits)):
                if self.structure[i] != 'x':
                    if self.structure[i] != bits[i]:
                        flag = False
            if flag == True:
                return True
        return False

                
    def isConstant(self):
        if "x" not in self.structure:
            return True 
        else:
            return False


    def getFieldType(self):
        if self.name.startswith("imm"):
            return "imm"
        elif self.name in (
                "Rm",
                "Rn",
                "Rd",
                "Rdm",
                "Rdn",
                "Rt",
                "Rt2",
                "Ra",
                "Rs",
                "Vm",
                "Vn",
                "Vd",
                "RdLo",
                "RdHi",
            ):
                return "reg"
        return self.name

    def get_fuzzlist(self):
        if 'x' in self.structure:
            l = self.structure.count('x')
            if self.type == 'cond':
                self.fuzz_list = ['1110']
            elif self.type == 'reg' and self.bits == 4:
                self.fuzz_list = special_regs_4bits + random.sample(left_regs_4bits, 2)
            elif self.type == 'reg' and  self.bits == 3:
                self.fuzz_list = special_regs_3bits + random.sample(left_regs_3bits, 1)
            elif self.type == 'register_list':
                self.fuzz_list = random.sample(bin_x(self.bits), self.bits)
            elif self.type == 'imm':
                xlists = find(self.structure,'x')
                if len(xlists)>10:
                    random_indexes = random.sample(xlists[1:-1],len(xlists)-10)
                    for i in random_indexes:
                        self.structure = self.structure[:i]+str(i%2)+self.structure[i+1:]
                all_imm = extend_insts([self.structure])
                special_imm = [all_imm[0], all_imm[-1]]
                left_imm = all_imm[1:-1]
                #if l <= 3:
                #    num = l * 2 - 2
                #else:
                #    num = 6
                if l >1:
                    self.fuzz_list = special_imm + random.sample(left_imm, l-2)
                else:
                    self.fuzz_list = special_imm
            else:
                if l == 1:
                    self.fuzz_list = extend_insts([self.structure])
                else:
                    self.fuzz_list = random.sample(extend_insts([self.structure]), l)
        else:
            self.structure = self.structure.replace('(', '').replace(')', '')
            self.fuzz_list = [self.structure]
        
    def get_constraints(self):
        constraints = []
        constraints.append(self.name +" >= 0")
        constraints.append(self.name +" < "+str(2**self.bits))
        return constraints


class InstEncoding:
    '''reprensentation of ASL code of encoding scheme'''
    def __init__(self,name,post,fields,decode,execute):
        self.name = name
        self.post = post
        self.fields = self.convertField(fields) 
        self.decode = decode 
        self.execute = execute
        self.conditions = self.extractConditions(self.decode.code) + self.extractConditions(self.execute.code)
        if post != None:
            self.conditions += self.extractConditions(self.post.code)
        self.valid_constraints = []
        self.unpredictable_constraints = []
        self.alias = self.generateAlias()





    def isThisEncoding(self,inst):
        flag = True 
        for field in self.fields:
            if field.isField(inst[31-field.start:32-field.end]) == False:
                flag = False

        return flag

    def decode_inst(self,inst):
        symbols = {}
        for field in self.fields:
            if "x" not in field.structure:
                continue
            symbols[field.name] = int(inst[31-field.start:32-field.end],2)
        return symbols

    def covered_constraints(self,insts):
        cover_constraints = {}
        for condition in self.valid_constraints:
            cover_constraints[condition.statement] = {}
            cover_constraints[condition.statement]["approve"] = False
            cover_constraints[condition.statement]["negate_approve"] = False
        

        for inst in insts:
            for condition in self.valid_constraints:
                if cover_constraints[condition.statement]["approve"] == True and \
                        cover_constraints[condition.statement]["negate_approve"] == True:
                            continue 

                approve, negate_approve = self.meet_constraint(condition,inst)
                if approve == True:
                    cover_constraints[condition.statement]["approve"] = True
                if negate_approve == True:
                    cover_constraints[condition.statement]["negate_approve"] = True
        return cover_constraints   



    def patchINStatement(self,statement):
        if "M32_User" in statement or "EL0" in statement:
            return []
        logic = " == "
        if statement.startswith("!"):
            logic = " != "
            statement = statement[1:]
            statement = removeBrackets(statement)
        conditions = []
        value_name = statement.split(" IN ")[0]
        values = eval(statement.split(" IN ")[1].replace("{","[").replace("}","]"))
        for v in values:
            conditions.append(value_name+logic+v)
        return conditions

    def convertField(self,fields):
        results = []
        for field in fields:
            results.append(Field(field[0],field[1],field[2],field[4]))
        return results


    def containField(self,value_name):
        for field in self.fields:
            if field.name == value_name:
                return field
        for field in self.fields:
            if field.name+" " in value_name or \
            field.name+"[" in value_name or \
            "("+field.name+")" in value_name:
                return field
        return None


    def addToField(self,field_name,value):
        print("add {} to field {}".format(value,field_name))
        for field in self.fields:
            if field.name == field_name:
                value = bin(value)[2:].zfill(field.bits)
                if value not in field.fuzz_list:
                    field.fuzz_list.append(value)
                

    def unpredictableConditions(self):
        results = []
        for line in (self.decode.code+self.execute.code).split("\n") :
            for statement in line.split(";"):
                if "UNPREDICTABLE" in statement:
                    print(statement)
                    for condition in self.valid_constraints:
                        if condition.orig_statement in statement:
                            print(condition)
                            results.append(condition)
        return results
        


    def isUnpredictable(self,inst):
        if not self.isThisEncoding(inst):
            return False 

        conditions = self.unpredictableConditions()
        for c in conditions:
            if self.meet_constraint(c,inst):
                return True 
        return False


    def extractConditions(self,code): 
        all_conditions = []
        if 'if' in code:
            conditions = handleIfStatement(code)
            all_conditions.extend(conditions)
        if 'case' in code:
            conditions = handleCaseStatement(code)
            all_conditions.extend(conditions)


        for line in code.split("\n"):
            for statement in line.split(";"):
                statement = removeConditionInStatement(statement,all_conditions)                

                find_condition = re.findall(r'(([\'[01x\s]+\']|[\w\'\,\[\]\+]+)\s(>=|<=|==|!=|>|<){1}\s+([\'[01x\s]+\']|[\w\']+))',statement)
                if len(find_condition) > 0:
                    for results in find_condition:
                        condition = results[0]
                        if condition.startswith("("):
                            condition = condition[1:]
                        if condition.endswith(")"):
                            condition = condition[:-1]
                        if condition not in all_conditions:
                            all_conditions.append(condition)
        return self.extractAtomicConditions(all_conditions)


    def patchSymbolicArray(self,atomicCondition):
        addedconditions = []
        orig_condition = atomicCondition
        results = re.findall(r'((\w+)\[([a-zA-Z]+)\])',atomicCondition)
        #rd[n] == xxx; unsolved by solver
        for result in results:
            addedconditions.append("%s == 0"%result[2])
            orig_condition = orig_condition.replace(result[0],"%s[0]"%result[1])
        addedconditions.append(orig_condition)
        return addedconditions


    def patchReadAPSR(self,atomicCondition):
        addedconditions = []
        results = re.findall("SysRegReadCanWriteAPSR\((\w)+\,\s+ThisInstr\(\)\)",atomicCondition)
        print(results)
        for result in results:
            addedconditions.append("%s == 14"%(result[0]))
            addedconditions.append("opc1 == 0")
            addedconditions.append("CRn == 0")
            addedconditions.append("CRm == 1")
            addedconditions.append("opc2 == 0")
        return addedconditions



    def patchElem(self,atomicCondition):
        if atomicCondition.startswith("(") and atomicCondition.endswith(")"):
            atomicConditin = atomicCondition[1:]
        addedconditions = []
        orig_condition = atomicCondition
        results = re.findall(r'(Elem\[([\w\+\[\]]+)\s*\,\s*(\w+)\s*\,\s*(\w+)\])',atomicCondition)
        for result in results:
            addedconditions.append("%s == 0"%result[2])
            addedconditions.append("%s == 1 or %s == 0"%(result[3],result[3]))
            orig_condition = orig_condition.replace(result[0],result[1].split("[")[0]+"[0]")
        addedconditions.append(orig_condition)
        return addedconditions

    def patchZeros(self,atomicCondition):
        results = re.findall(r'Zeros\(.+\)',atomicCondition)
        for result in results:
            atomicCondition = atomicCondition.replace(result[0],"0")
        return atomicCondition

    def patchIsZero(self,atomicCondition):
        results = re.findall(r'IsZero\((.+)\)',atomicCondition)
        if len(results) > 0:
            if "!IsZero" in atomicCondition or "! IsZero" in atomicCondition:
                return "%s == 1"%results[0]
            else:
                return "%s == 0"%results[0]
        return atomicCondition

    def patchStateFunction(self,atomicCondition):
        if "ExclusiveMonitorsPass" in atomicCondition:
            return None
        return atomicCondition


    def extractAtomicConditions(self,conditions):
        allAtomicConditions = []
        print(conditions)
        for condition in conditions:
            #condition = removeBrackets(condition)
            split_ors = condition.split("||")
            for split_or in split_ors:
                #split_or = removeBrackets(split_or)
                atomicConditions = split_or.split("&&")
                for atomicCondition in atomicConditions:
                    atomicConditions = self.patchZeros(atomicCondition)
                    if  self.patchStateFunction(atomicCondition) == None:
                        continue

                    atomicCondition = removeBrackets(atomicCondition.strip())
                    atomicCondition = self.patchIsZero(atomicCondition)

                    patchReadAPSRConditions = self.patchReadAPSR(atomicCondition)
                    if len(patchReadAPSRConditions) > 0:
                        for c in patchReadAPSRConditions:
                            allAtomicConditions.append(Condition(c,self.fields,True))
                        continue
                    
                    patchElemConditions = self.patchElem(atomicCondition)
                    if len(patchElemConditions) > 1:
                        for c in patchElemConditions:
                            allAtomicConditions.append(Condition(c,self.fields,True))
                        continue


                    if atomicCondition.startswith("(") and not atomicCondition.startswith("()"):
                        atomicCondition = atomicCondition[1:]


                    if atomicCondition.endswith(")") and not atomicCondition.endswith("()"):
                        atomicCondition = atomicCondition[:-1]
                    if "(" in atomicCondition and ")" not in atomicCondition:
                        atomicCondition = atomicCondition.replace("(","")
                    if ")" in atomicCondition and "(" not in atomicCondition:
                        atomicCondition = atomicCondition.replace(")","")
                    if atomicCondition.startswith("! "):
                        atomicCondition = atomicCondition.replace("! ","!")
                    if len(atomicCondition.split(" ")) == 1: 
                        continue
                    if atomicCondition.split(" ")[-1] == "True" or atomicCondition.split(" ")[-1] == "False":
                        continue


                    if " IN " in atomicCondition:
                        conditions = self.patchINStatement(atomicCondition)
                        for c in conditions:
                            allAtomicConditions.append(Condition(c,self.fields,True))
                        continue

                    patchSymbolicConditions = self.patchSymbolicArray(atomicCondition)
                    for c in patchSymbolicConditions:
                        allAtomicConditions.append(Condition(c,self.fields,True))
        return allAtomicConditions


    def generateAlias(self):
        results = {}
        statements = self.decode.code.split(";")
        statements = split_by(statements,"\n") 
        for statement in statements:
            result = analyzeOneStatement(statement.strip())
            for key in result:
                if key not in results:
                    results[key] = result[key]
                else:
                    results[key].extend(result[key])
        return results



    def generate_insts(self):
        results = []
        for field in self.fields:
            field.get_fuzzlist()
        for condition in self.conditions:
            results = self.solve(condition)
        
        insts = [""]
        for field in self.fields:
            insts = extend_seedlist(insts,field.fuzz_list)
        return list(set(insts))


    def get_variable_constraints(self,condition):
        if condition.statement in self.analyzed_condition:
            return [],[]
        else:
            self.analyzed_condition.append(condition.statement)
        v_results = []
        c_results = []
        variables = condition.get_variables()
        for v in variables:
            v_results.append(v)
            if v in self.alias:
                if len(self.alias[v]) == 1:
                    if "==" in self.alias[v][0]:
                        continue
                    c_results.append("%s == %s"%(v,self.alias[v][0]))
                    v_a_results,c_a_results = self.get_variable_constraints(Condition("%s == %s"%(v,self.alias[v][0]),self.fields))
                else:
                    tmp_constraints = []
                    for v_a in self.alias[v]:
                        tmp_constraints.append("%s == %s"%(v,v_a))
                    c_results.append(" or ".join(tmp_constraints))
                    v_a_results,c_a_results = self.get_variable_constraints(Condition(" or ".join(tmp_constraints),self.fields))
                        
                v_results.extend(v_a_results)
                c_results.extend(c_a_results)

        return list(set(v_results)), list(set(c_results))



    def meet_constraint(self,condition,instruction):
        print("whether %s meets %s for %s"%(instruction,condition,self.name))
        approve = False
        negate_approve = False
        symbols = self.decode_inst(instruction)

        if "operand[bit_pos] == bit_val" in condition.statement:
            return
        z3_s = Solver()
        
        self.analyzed_condition = []
        variables,constraints = self.get_variable_constraints(condition)

        for v in variables:
            print("related variable %s"%v)
            v_field =  self.containField(v)
            if v_field == None:
                if v.endswith("()"):
                    continue 
                if v == "True" or v == "False":
                    continue 
                print("init variable %s = BitVec('%s',32)"%(v,v))
                exec("%s = BitVec('%s',32)"%(v,v))

        for field in self.fields:
            #print("%s start:%s end:%s structure:%s"%(field.name, field.start, field.end,field.structure))
            if field.name != "_":
                #print("init field %s = BitVec('%s',32)"%(field.name,field.name))
                exec("%s = BitVec('%s',32)"%(field.name,field.name))


        for ite_c in constraints:
            constraint = Condition(ite_c,self.fields).get_constraint(self.fields)
            z3_s.add(eval(constraint))

        
               
        z3_s.add(eval(condition.get_constraint(self.fields)))


        for symbol in symbols:
            #print("instruction has symbol %s == %s"%(symbol,str(symbols[symbol])))
            z3_s.add(eval("%s == %s"%(symbol,str(symbols[symbol]))))


        if z3_s.check() == sat:
            approve = True


    #==================================
    #Negate the constraint and solve it

        z3_s.reset()


        for ite_c in constraints:
            constraint = Condition(ite_c,self.fields).get_constraint(self.fields)
            z3_s.add(eval(constraint))

               
        z3_s.add(eval(condition.negate_statement))


        if z3_s.check() == sat:
            negate_approve = True 
        return approve, negate_approve
 
    


    def solve(self,condition):
        global all_constraint
        global all_valid_constraint 
        global all_solved_constraint

        all_constraint += 2
        print("Solve the condition {}-------------------------".format(condition))
        if "operand[bit_pos] == bit_val" in condition.statement:
            return
        z3_s = Solver()
        
        self.analyzed_condition = []
        variables,constraints = self.get_variable_constraints(condition)
        print(variables)
        print(constraints)

        flag = False
        
        all_field_variables = []
        for v in variables:
            v_field =  self.containField(v)
            if v_field: 
                if not v_field.isConstant():
                    flag = True
                exec("%s = BitVec('%s',32)"%(v_field.name,v_field.name))
                all_field_variables.append(eval(v_field.name))
                for c in v_field.get_constraints():
                    z3_s.add(eval(c))
            else:
                if v.endswith("()"):
                    continue 
                if v == "True" or v == "False":
                    continue 
                exec("%s = BitVec('%s',32)"%(v,v))

        
        if flag == False:
            return
        
        self.valid_constraints.append(condition)
        all_valid_constraint += 1

        for c in constraints:
            constraint = Condition(c,self.fields).get_constraint(self.fields)
            z3_s.add(eval(constraint))

        
               
        z3_s.add(eval(condition.get_constraint(self.fields)))


        if z3_s.check() == sat:
            all_solved_constraint += 1
            results = z3_s.model()
            for v in all_field_variables:
                try:
                    value = results.eval(v).as_long()
                    self.addToField(str(v),value)
                except:
                    pass
        else:
            fail_solved_constraint.append(self.name+":"+str(condition))

    #==================================
    #Negate the constraint and solve it

        z3_s.reset()

        all_valid_constraint += 1
        for v in variables:
            v_field =  self.containField(v)
            if v_field:
                for c in v_field.get_constraints():
                    z3_s.add(eval(c))

        for c in constraints:
            constraint = Condition(c,self.fields).get_constraint(self.fields)
            z3_s.add(eval(constraint))

               
        z3_s.add(eval(condition.negate_statement))


        if z3_s.check() == sat:
            all_solved_constraint += 1
            results = z3_s.model()
            for v in all_field_variables:
                try:
                    value = results.eval(v).as_long()
                    self.addToField(str(v),value)
                except:
                    pass
        





class ASL:
    '''Representation of ASL code consisting of the code, list of names it defines and list of dependencies'''

    def __init__(self, name, code, defs, deps):
        self.name = name
        self.code = code
        self.defs = defs
        self.deps = deps

    def emit(self, file, tag):
        emit(file, tag, self.code)

    def put(self, ofile, indent):
        for l in self.code.splitlines():
            print(" "*indent + l, file=ofile)

    def __str__(self):
        return "ASL{"+", ".join([self.name, str(self.defs), str(self.deps)])+"}"

    # workaround: patch all ASL code with extra dependencies
    def patchDependencies(self, chunks):
        for line in self.code.splitlines():
            l = re.split('//', line)[0]  # drop comments
            for m in re.finditer('''([a-zA-Z_]\w+(\.\w+)?\[?)''', l):
                n = m.group(1)
                if n in chunks:
                    self.deps |= {chunks[n].name}
                    self.deps |= {n}
                    # print("Adding dep", n, chunks[n].name)
        self.deps -= self.defs
        # Workaround: ProcState SP field incorrectly handled
        if self.name == "shared/functions/system/ProcState": self.deps -= {"SP", "SP.write.none"}
        if "Unpredictable_WBOVERLAPST" in self.defs: self.deps -= {"PSTATE"}

    # workaround: v8-A code still uses the keyword 'type' as a variable name
    # change that to 'type1'
    def patchTypeVar(self):
        self.code = patchTypeAsVar(self.code)

    def toPrototype(self):
        '''Strip function bodies out of ASL
           This is used when a function is cut but we still need to keep
           the function body.'''
        # build groups of lines based on whether they have matching numbers of parentheses
        groups = []
        group  = []
        parens = 0
        for l in self.code.splitlines():
            group.append(l)
            # update count of matching parentheses
            openers = len(re.findall('[([]', l))
            closers = len(re.findall('[)\]]', l))
            parens = parens + openers - closers
            if parens == 0:
                groups.append(group)
                group = []
        # crude heuristic for function bodies: starts with blank chars
        # beware: only works if the ASL block only contains functions
        lines = [ l for g in groups if not g[0].startswith("    ") for l in g ]
        # print("Generating prototype for "+self.name)
        # print("  "+"\n  ".join(lines))
        return ASL(self.name, '\n'.join(lines), self.defs, set())

# Test whether instruction encoding has a field with given name
def hasField(fields, nm):
    return any(f == nm for (_, _, f, _, _) in fields)

# Turn instruction and encoding names into identifiers
# e.g., "aarch32/UHSAX/A1_A" becomes "aarch32_UHSAX_A1_A"
# and remove dots from "LDNT1D_Z.P.BR_Contiguous"
def deslash(nm):
    return nm.replace("/instrs","").replace("/", "_").replace("-","_").replace(".","_")

class Instruction:
    '''Representation of Instructions'''

    def __init__(self, name, encs, post, conditional, exec):
        self.name = name
        self.encs = encs
        self.post = post
        self.conditional = conditional
        self.exec = exec
        self.instEncodings = []
        self.file_name = ""

    def emit_asl_syntax(self, ofile):
        
        print("__instruction "+ deslash(self.name)+"_"+self.file_name, file=ofile)

        for (inm,insn_set,fields,dec) in self.encs:
            unpreds = []
            pattern = "" # todo: assumes that fields are sorted in order

            print("    __encoding "+ deslash(inm), file=ofile)
            print("        __instruction_set "+ insn_set, file=ofile)
            for (hi, lo, nm, split, consts) in fields:
                # assert(not split) todo
                wd = (hi - lo) + 1

                if re.fullmatch("(\([01]\))+", nm):
                    # workaround
                    consts = nm
                    nm = '_'

                # convert all the 'should be' bits to 'unpredictable_unless'
                cs = ""
                i  = hi
                while consts != "":
                    if consts.startswith("(1)") or consts.startswith("(0)"):
                        unpreds.append((i, consts[1]))
                        cs = cs + "x"
                        consts = consts[3:]
                    elif consts[0] in "01x":
                        cs = cs + consts[0]
                        consts = consts[1:]
                    else:
                        print("Malformed field "+consts)
                        assert False
                    i = i - 1
                consts = cs
                assert len(consts) == wd
                pattern = pattern + consts
                nm = patchTypeAsVar(nm) # workaround
                if nm != "_":
                    print("        __field "+nm+" "+str(lo)+" +: "+str(wd), file=ofile)
            pattern = [ pattern[i:i+8] for i in range(0, len(pattern), 8) ]
            print("        __opcode '" + " ".join(pattern) + "'", file=ofile)
            guard = "cond != '1111'" if  insn_set == "A32" and hasField(fields, "cond") else "TRUE";
            print("        __guard "+guard, file=ofile)
            for (i, v) in unpreds:
                print("        __unpredictable_unless "+str(i)+" == '"+v+"'", file=ofile)

            print("        __decode", file=ofile)
            dec.put(ofile, 12)
            print(file=ofile)
        if self.post:
            print("    __postdecode", file=ofile)
            self.post.patchTypeVar()
            self.post.put(ofile, 8)
        if self.conditional:
            print("    __execute __conditional", file=ofile)
        else:
            print("    __execute", file=ofile)
        self.exec.patchTypeVar()
        self.exec.put(ofile, 8)

    def emit_tag_syntax(self, file):
        index = [] # index of sections of this instruction
        exec_tag = self.name+':execute'
        post_tag = self.name+':postdecode'
        idx_tag  = self.name+':index'
        self.exec.emit(file, exec_tag)
        index.append('Execute: '+exec_tag)
        if self.post:
            self.post.emit(file, post_tag)
            index.append('Postdecode: '+post_tag)
        for (inm,insn_set,fields,dec) in self.encs:
            dec_tag  = inm + ':decode'
            enc_tag  = inm + ':diagram'
            enc = [insn_set]
            enc.extend([str(hi)+":"+str(lo)+" "+nm+" "+consts
                        for (hi,lo,nm,_,consts) in fields ])
            emit(file, enc_tag, "\n".join(enc))
            dec.emit(file, dec_tag)
            index.append('Decode: '+dec_tag+'@'+enc_tag)
        emit(file, idx_tag, "\n".join(index))

    def emit_sail_ast(self, previous_clauses, file):
        for enc in self.encs:
            enc_name, enc_iset, enc_fields, enc_asl = enc
            fields = [(nm, hi - lo + 1) for (hi, lo, nm, split, consts) in enc_fields if nm != '_']
            typed_fields = ['/* {} : */ bits({})'.format(name, length)  for (name, length) in fields]
            if len(typed_fields) < 1:
                clause = 'union clause ast = ' + sanitize(enc_name) + ' : unit'
            else:
                clause = 'union clause ast = ' + sanitize(enc_name) + ' : (' + ', '.join(typed_fields) + ')'
            if clause not in previous_clauses:
                print(clause, file=file)
                previous_clauses.add(clause)


    def emit_insts(self,file,target_set):
        global all_encoding
        global all_insts
        for (inm, insn_set, fields, dec) in self.encs:
            if insn_set != target_set:
                continue
            all_encoding += 1
            instencoding = InstEncoding(inm,self.post,fields,dec,self.exec)
            insts = instencoding.generate_insts()
            all_insts += len(insts)
            #insts = self.fuzz_insts(fields,dec)
            for inst in insts:
                if insn_set == "A64":
                    file.write("%s %s %s\n"%(deslash(inm)+"_"+self.file_name,insn_set,inst))
                else:
                    file.write("%s %s %s\n"%(deslash(inm),insn_set,inst))

                    



    def fuzz_insts(self,fields,dec):
        dec_code = dec.code
        execute = self.exec.code 
        fuzz_field = {}
        for field in fields:
            value_name = field[2]
            value_structure = field[4]
            value_type = value_name
            if value_name not in fuzz_field:
                fuzz_field[value_name] = {}
            fuzz_field[value_name]["structure"] = value_structure

            # value_type: cond, reg, imm, register_list
            if value_name.startswith("imm"):
                value_type = "imm"
            elif value_name in (
                "Rm",
                "Rn",
                "Rd",
                "Rdm",
                "Rdn",
                "Rt",
                "Rt2",
                "Ra",
                "Rs",
                "Vm",
                "Vn",
                "Vd",
                "RdLo",
                "RdHi",
            ):
                value_type = "reg"
            fuzz_field[value_name]["value_type"] = value_type


            if 'x' in value_structure:
                l = value_structure.count('x')
                if value_type == 'cond':
                    fuzz_list = ['1110']
                elif value_type == 'reg' and len(value_structure) == 4:
                    fuzz_list = special_regs_4bits + random.sample(left_regs_4bits, 2)
                elif value_type == 'reg' and len(value_structure) == 3:
                    fuzz_list = special_regs_3bits + random.sample(left_regs_3bits, 1)
                elif value_type == 'register_list':
                    fuzz_list = random.sample(bin_x(self.bits), self.bits)
                elif value_type == 'imm':
                    all_imm = extend_insts([value_structure])
                    special_imm = [all_imm[0], all_imm[-1]]
                    left_imm = all_imm[1:-1]
                    if l <= 4:
                        num = l * 2 - 2
                    else:
                        num = 8
                    fuzz_list = special_imm + random.sample(left_imm, num)
                else:
                    fuzz_list = random.sample(extend_insts([value_structure]), l * 2)
            else:
                value_structure = value_structure.replace('(', '').replace(')', '')
                fuzz_list = [value_structure]
            fuzz_field[value_name]["fuzz_list"] = fuzz_list


        fuzz_field = self.add_extra_list(fuzz_field,dec)

        print(fuzz_field)
        print("")
        # travese all the fuzz_list
        insts = ['']
        for field in fields:
            insts = extend_seedlist(insts,fuzz_field[field[2]]["fuzz_list"])
        return insts


    def add_extra_list(self,fuzz_field,dec):
        dec_code = dec.code 
        # 1.handle the decoding asl code
        # 1.1: conduct data flow analysis so that the execute asl can recognize the value name
        alias = analyzeDecodeASL(dec.code) 
        print(alias)
        # 1.2: collect the branch statement: if then; case of;
        print("Now adding the extra list with program analysis")
        conditions = extractConditions(dec_code)
        #atomicConditions = extractAtomicConditions(conditions)
        for condition in conditions:
            #print("condition is {}".format(condition))
            #splitedCondition= splitCondition(condition)
            #condition_name = splitedCondition[0].strip()
            #condition_value = splitedCondition[1].strip()
            #if condition_value.startswith("'") and condition_value.endswith("'"):
            #    condition_value = condition_value[1:-1]
            
            #negate_condition_value = negateOneZero(condition_value)
            condition.solve_value()
            #print("add the condition value")
            fuzz_field = addValueToFuzzField(condition_name,condition_value,fuzz_field,alias)
            #print("add the negated condition value")
            #fuzz_field = addValueToFuzzField(condition_name,negate_condition_value,fuzz_field,alias)
        # Done !

        # 2.handle the execute asl code 
        # 2.1 collect the branch statement: if then; case of;
        exec_code = self.exec.code
        conditions = extractConditions(exec_code)
        #atomicConditions = extractAtomicConditions(conditions)
        #print(atomicConditions)
        for condition in conditions:
            splitedCondition = splitCondition(condition)
            condition_name = splitedCondition[0].strip() 
            condition_value = splitedCondition[1].strip() 
            if condition_value.startswith("'") and condition_value.endswith("'"):
                condition_value = condition_value[1:-1]

            #negate_condition_value = negateOneZero(condition_value)
            
            print("add the %s with value %s"%(condition_name,condition_value))
            fuzz_field = addValueToFuzzField(condition_name,condition_value,fuzz_field,alias)
            #print("add the %s with value %s"%(condition_name,negate_condition_value))

            #fuzz_field = addValueToFuzzField(condition_name,negate_condition_value,fuzz_field,alias)

        return fuzz_field


            



    def __str__(self):
        encs = "["+ ", ".join([inm for (inm,_,_,_) in self.encs]) +"]"
        return "Instruction{" + ", ".join([encs, (self.post.name if self.post else "-"), self.exec.name])+", "+conditional+"}"


########################################################################
# Extracting information from XML files
########################################################################

alt_slice_syntax = False
demangle_instr = False

'''
Read pseudocode to extract ASL.
'''
def readASL(ps):
    name = ps.attrib["name"]
    name = name.replace(".txt","")
    name = name.replace("/instrs","")
    name = name.replace("/Op_","/")
    chunk = ps.find("pstext")

    # list of things defined in this chunk
    defs = { x.attrib['link'] for x in chunk.findall('anchor') }

    # extract dependencies from hyperlinks in the XML
    deps = { x.attrib['link'] for x in chunk.findall('a') if not x.text.startswith("SEE") }

    # drop impl- prefixes in links
    deps = { re.sub('(impl-\w+\.)','',x) for x in deps }
    defs = { re.sub('(impl-\w+\.)','',x) for x in defs }

    # drop file references in links
    deps = { re.sub('([^#]+#)','',x) for x in deps }

    code = ET.tostring(chunk, method="text").decode().rstrip()+"\n"

    # workaround: patch operator precedence error
    code = code.replace("= e - e MOD eltspersegment;",  "= e - (e MOD eltspersegment);")
    code = code.replace("= p - p MOD pairspersegment;", "= p - (p MOD pairspersegment);")

    if alt_slice_syntax:
        code = "\n".join(map(patchSlices, code.split('\n')))

    return ASL(name, code, defs, deps)


'''
Classic ASL syntax has a syntax ambiguity involving the use of
angles (< and >) both to delimit bitslices and as comparision
operators.
We make parsing easier by converting bitslices to use square brackets
using a set of heuristics to distinguish bitslices from comparisions.
'''
def patchSlices(x):
    reIndex = r'[0-9a-zA-Z_+*:\-()[\]., ]+'
    rePart = reIndex
    reParts = rePart+"(,"+rePart+")*"
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    x = re.sub("<("+reParts+")>", r'[\1]',x)
    return x

'''
Read encoding diagrams header found in encoding index XML
'''
def readDiagram(reg):
    size = reg.attrib['form']

    fields = []
    for b in reg.findall('box'):
        wd = int(b.attrib.get('width','1'))
        hi = int(b.attrib['hibit'])
        # normalise T16 reg bit numbers
        lo = hi - wd + 1
        fields.append((lo, wd))
    return (size, fields)

def squote(s):
    return "'"+s+"'"

'''
Convert a field in a decode table such as "111" or "!= 111" or None
to a legal ASL pattern
'''
def fieldToPattern(f):
    if f:
        return "!"+squote(f[3:]) if f.startswith('!= ') else squote(f)
    else:
        return "_"

'''
Read encoding diagrams entries found in encoding index XML
'''
def readDecode(d, columns):
    values = {}
    for b in d.findall('box'):
        wd = int(b.attrib.get('width','1'))
        hi = int(b.attrib['hibit'])
        lo = hi - wd + 1
        values[lo] = fieldToPattern(b.find('c').text)
    return [ values.get(lo, "_") for (lo, _) in columns ]

def readIClass(c):
    label = c.attrib['iclass']
    allocated = c.attrib.get("unallocated", "0") == "0"
    predictable = c.attrib.get("unpredictable", "0") == "0"
    assert allocated or predictable
    # print("Reading iclass "+label+" "+str(allocated)+" "+str(unpredictable))
    return (label, allocated, predictable)

'''
'''
def readGroup(label, g):
    # print("Reading group "+label)
    diagram = readDiagram(g.find("regdiagram"))
    # print("Diagram "+str(diagram))

    children = []

    for n in g.findall('node'):
        dec = readDecode(n.find('decode'), diagram[1])
        # print("Decode "+str(dec), diagram[1])
        if 'iclass' in n.attrib:
            i = readIClass(n)
            children.append((dec, False, i))
        elif 'groupname' in n.attrib:
            nm = n.attrib['groupname']
            g = readGroup(nm, n)
            children.append((dec, True, g))
        else:
            assert False
    return (label, diagram, children)

'''
'''
def readInstrName(dir, filename, encname):
    filename = dir+"/"+filename
    xml = ET.parse(filename)
    for ic in xml.findall(".//iclass"):
        decode = ic.find("regdiagram").attrib['psname']
        for enc in ic.findall("encoding"):
            if not encname or enc.attrib['name'] == encname:
                decode = decode.replace(".txt","")
                decode = decode.replace("/instrs","")
                decode = decode.replace("-","_")
                decode = decode.replace("/","_")
                return decode
    assert False

'''
'''
def readITables(dir, root):
    classes = {}
    funcgroup = None # hack: structure of XML is not quite hierarchial
    for child in root.iter():
        if child.tag == 'funcgroupheader':
            funcgroup = child.attrib['id']
            # print("Functional Group "+funcgroup)
        elif child.tag == 'iclass_sect':
            iclass_id = child.attrib['id']
            fields = [ (b.attrib['name'], int(b.attrib['hibit']), int(b.attrib.get('width', 1))) for b in child.findall('regdiagram/box') if 'name' in b.attrib ]
            # print("Group "+funcgroup +" "+ iclass_id +' '+str(fields))
            tables = []
            for i in child.findall('instructiontable'):
                iclass = i.attrib['iclass']
                headers = [ r.text for r in i.findall('thead/tr/th') if r.attrib['class'] == 'bitfields' ]
                headers = [ patchTypeAsVar(nm) for nm in headers ] # workaround
                # print("ITable "+funcgroup +" "+ iclass +" "+str(headers))
                rows = []
                for r in i.findall('tbody/tr'):
                    patterns = [ fieldToPattern(d.text) for d in r.findall('td') if d.attrib['class'] == 'bitfield' ]
                    undef    = r.get('undef', '0') == '1'
                    unpred   = r.get('unpred', '0') == '1'
                    nop      = r.get('reserved_nop_hint', '0') == '1'
                    encname  = r.get('encname')
                    nm       = "_" if undef or unpred or nop else readInstrName(dir, r.attrib['iformfile'], encname)
                    rows.append((patterns, nm, encname, undef, unpred, nop))
                tables.append((iclass, headers, rows))
                # print(iclass, fields, headers, rows)
            assert len(tables) == 1
            # discard fields that are not used to select instruction
            # fields = [ (nm, hi, wd) for (nm, hi, wd) in fields if nm in headers ]
            fields = [ (patchTypeAsVar(nm), hi, wd) for (nm, hi, wd) in fields ] # workaround
            classes[iclass_id] = (fields, tables[0])
    return classes

'''
'''
def readDecodeFile(dir, file):
    print("Reading decoder "+file)
    root = ET.parse(file)

    iset = root.getroot().attrib['instructionset']
    groups = readGroup(iset, root.find('hierarchy'))

    classes = readITables(dir, root)

    return (groups, classes)

def ppslice(f):
    (lo, wd) = f
    return (str(lo) +" +: "+ str(wd))

def printITable(ofile, level, c):
    (fields, (ic, hdr, rows)) = c
    for (fnm, hi, wd) in fields:
        print("    "*level + "__field "+ fnm +" "+str(hi-wd+1) +" +: "+str(wd), file=ofile)
    print("    "*level +"case ("+ ", ".join(hdr) +") of", file=ofile)
    for (pats, nm, encname, undef, unpred, nop) in rows:
        nm = "__encoding "+deslash(nm)
        if encname: nm = nm + " // " +encname
        if undef: nm = "__UNALLOCATED"
        if unpred: nm = "__UNPREDICTABLE"
        if nop: nm = "__NOP"
        print("    "*(level+1) +"when ("+ ", ".join(pats) +") => "+ nm, file=ofile)
    return

def printDiagram(ofile, level, reg):
    (size, fields) = reg
    print("    "*level +"case ("+ ", ".join(map(ppslice, fields)) +") of", file=ofile)
    return

def printGroup(ofile, classes, level, root):
    (label, diagram, children) = root
    print("    "*level + "// "+label, file=ofile)
    printDiagram(ofile, level, diagram)
    for (dec, isGroup, c) in children:
        if isGroup:
            print("    "*(level+1) +"when ("+ ", ".join(dec) +") =>", file=ofile)
            printGroup(ofile, classes, level+2, c)
        else:
            (label, allocated, predictable) = c
            tag = "// "+label
            if allocated and predictable:
                (fields, (ic, hdr, rows)) = classes[label]
                print("    "*(level+1) +"when ("+ ", ".join(dec) +") => " +tag, file=ofile)
                printITable(ofile, level+2, classes[label])
            else:
                if not allocated: tag = "__UNPREDICTABLE"
                if not predictable: tag = "__UNALLOCATED"
                print("    "*(level+1) +"when ("+ ", ".join(dec) +") => " +tag, file=ofile)

    return

def printDecodeTree(ofile, groups, classes):
    print("__decode", groups[0], file=ofile)
    printGroup(ofile, classes, 1, groups)

'''
Read shared pseudocode files to extract ASL.
Result is sorted so that uses come before definitions.
'''
def readShared(files):
    asl = {}
    names = set()
    for f in files:
        xml = ET.parse(f)
        for ps in xml.findall('.//ps_section/ps'):
            r = readASL(ps)
            # workaround: patch use of type as a variable name
            r.patchTypeVar()
            # workaround: patch SCTLR[] definition
            if r.name == "aarch64/functions/sysregisters/SCTLR":
                r.code = r.code.replace("bits(32) r;", "bits(64) r;")
            # workaround: patch AArch64.CheckUnallocatedSystemAccess
            if r.name == "aarch64/functions/system/AArch64.CheckUnallocatedSystemAccess":
                r.code = r.code.replace("bits(2) op0,", "bits(2) el, bits(2) op0,")
            # workaround: patch AArch64.CheckSystemAccess
            if r.name == "aarch64/functions/system/AArch64.CheckSystemAccess":
                r.code = r.code.replace("AArch64.CheckSVESystemRegisterTraps(op0, op1, crn, crm, op2);",
                                        "AArch64.CheckSVESystemRegisterTraps(op0, op1, crn, crm, op2, read);")

            # workaround: collect type definitions
            for m in re.finditer('''(?m)^(enumeration|type)\s+(\S+)''',r.code):
                r.defs.add(m.group(2))
                names |= {m.group(2)}
            # workaround: collect variable definitions
            for m in re.finditer('''(?m)^(\S+)\s+([a-zA-Z_]\w+);''',r.code):
                if m.group(1) != "type":
                    # print("variable declaration", m[1], m[2])
                    r.defs.add(m.group(2))
                    names |= {m.group(2)}
            # workaround: collect array definitions
            for m in re.finditer('''(?m)^array\s+(\S+)\s+([a-zA-Z_]\w+)''',r.code):
                # print("array declaration", m[1], m[2])
                v = m.group(2)+"["
                r.defs.add(v)
                names |= {v}
            # workaround: collect variable accessors
            for m in re.finditer('''(?m)^(\w\S+)\s+([a-zA-Z_]\w+)\s*$''',r.code):
                # print("variable accessor", m[1], m[2])
                r.defs.add(m.group(2))
                names |= {m.group(2)}
            # workaround: collect array accessors
            for m in re.finditer('''(?m)^(\w\S+)\s+([a-zA-Z_]\w+)\[''',r.code):
                # print("array accessor", m[1], m[2])
                v = m.group(2)+"["
                r.defs.add(v)
                names |= {v}
            # workaround: add PSTATE definition/dependency
            if r.name == 'shared/functions/system/PSTATE': r.defs.add("PSTATE")
            if "PSTATE" in r.code: r.deps.add("PSTATE")

            # workaround: skip standard library functions
            if r.name in [
                'shared/functions/common/SInt',
                'shared/functions/common/UInt',
                'shared/functions/common/Ones',
                'shared/functions/common/Zeros',
                'shared/functions/common/IsOnes',
                'shared/functions/common/IsZero',
                'shared/functions/common/SignExtend',
                'shared/functions/common/ZeroExtend',
                'shared/functions/common/Replicate',
                'shared/functions/common/RoundDown',
                'shared/functions/common/RoundUp',
                'shared/functions/common/RoundTowardsZero',
                ]:
                continue

            asl[r.name] = r

    return (asl, names)


'''
Read ARM's license notice from an XML file.
Convert unicode characters to ASCII equivalents (e.g,, (C)).
Return a giant comment block containing the notice.
'''
def readNotice(xml):
    # Read proprietary notice
    notice = ['/'*72, "// Proprietary Notice"]
    for p in xml.iter('para'):
        para = ET.tostring(p, method='text').decode().rstrip()
        para = para.replace("&#8217;", "'")
        para = para.replace("&#8220;", '"')
        para = para.replace("&#8221;", '"')
        para = para.replace("&#8482;", '(TM)')
        para = para.replace("&#169;", '(C)')
        para = para.replace("&#174;", '(R)')
        lines = [ ('// '+l).rstrip() for l in para.split('\n') ]
        notice.extend(lines)
    notice.append('/'*72)
    return '\n'.join(notice)

def sanitize(name):
    new_name = ""
    for c in name:
        if c not in string.ascii_letters and c not in string.digits:
            new_name += "_"
        else:
            new_name += c
    return new_name

# remove one level of indentation from code
def indent(code):
    return [ "    " + l for l in code ]

# remove one level of indentation from code
def unindent(code):
    cs = []
    for l in code:
        if l != "" and l[0:4] != "    ":
            print("Malformed conditional code '" + l[0:4] +"'")
            assert False
        cs.append(l[4:])
    return cs

# Execute ASL code often has a header like this:
#
#     if ConditionPassed() then
#         EncodingSpecificOperations();
#
# that we need to transform into a more usable form.
# Other patterns found are:
# - declaring an enumeration before the instruction
# - inserting another line of code between the first and second lines.
#   eg "if PSTATE.EL == EL2 then UNPREDICTABLE;"
# - wrapping the entire instruction in
#    "if code[0].startswith("if CurrentInstrSet() == InstrSet_A32 then"):
#
# Return value consists of (top, cond, dec, exec):
# - additional top level declarations (of enumerations)
# - boolean: is the instruction conditional?
# - additional decode logic (to be added to start of decode ASL)
# - demangled execute logic
def demangleExecuteASL(code):
    tops = None
    conditional = False
    decode = None
    if code[0].startswith("enumeration ") and code[1] == "":
        tops = code[0]
        code = code[2:]
    if code[0].startswith("if CurrentInstrSet() == InstrSet_A32 then"):
        first = code[0]
        code = code[1:]
        mid = code.index("else")
        code1 = unindent(code[:mid])
        code2= unindent(code[mid+1:])
        (tops1, conditional1, decode1, code1) = demangleExecuteASL(code1)
        (tops2, conditional2, decode2, code2) = demangleExecuteASL(code2)
        assert tops1 == None and tops2 == None
        assert conditional1 == conditional2
        code = [first] + indent(code1) + ["else"] + indent(code2)
        ([], conditional1, "\n".join([decode1 or "", decode2 or ""]), code)

    if code[0] == "if ConditionPassed() then":
        conditional = True
        code = code[1:] # delete first line
        code = unindent(code)
    if code[0] == "bits(128) result;":
        tmp = code[0]
        code[0] = code[1]
        code[1] = tmp
    elif len(code) >= 2 and code[1] == "EncodingSpecificOperations();":
        decode = code[0]
        code = code[1:]
    if code[0].startswith("EncodingSpecificOperations();"):
        rest = code[0][29:].strip()
        if rest == "":
            code = code[1:]
        else:
            code[0] = rest
    return (tops, conditional, decode, code)

def readInstruction(xml,names,sailhack):
    execs = xml.findall(".//pstext[@section='Execute']/..")
    posts = xml.findall(".//pstext[@section='Postdecode']/..")
    assert(len(posts) <= 1)
    assert(len(execs) <= 1)
    if not execs: return (None, None) # discard aliases

    exec = readASL(execs[0])
    post = readASL(posts[0]) if posts else None

    if demangle_instr:
        # demangle execute code
        code = exec.code.splitlines()
        (top, conditional, decode, execute) = demangleExecuteASL(code)
        exec.code = '\n'.join(execute)
    else:
        top = None
        conditional = False
        decode = None

    exec.patchDependencies(names)
    if post: post.patchDependencies(names)

    include_matches = include_regex is None or include_regex.search(exec.name)
    exclude_matches = exclude_regex is not None and exclude_regex.search(exec.name)
    if not include_matches or exclude_matches:
        return None


    # for each encoding, read instructions encoding, matching decode ASL and index
    encs = []
    for iclass in xml.findall('.//classes/iclass'):
        encoding = iclass.find('regdiagram')
        isT16 = encoding.attrib['form'] == "16"
        insn_set = "T16" if isT16 else iclass.attrib['isa']

        fields = []
        for b in encoding.findall('box'):
            wd = int(b.attrib.get('width','1'))
            hi = int(b.attrib['hibit'])
            lo = hi - wd + 1
            nm  = b.attrib.get('name', '_') if b.attrib.get('usename', '0') == '1' else '_'
            # workaround for Sail
            if sailhack and nm == 'type': nm = 'typ'
            consts = ''.join([ 'x'*int(c.attrib.get('colspan','1')) if c.text is None  else c.text for c in b.findall('c') ])
            if len(consts)!=wd and 'psbits' in b.attrib and b.attrib['psbits'] == 'x'*wd:
                consts = 'x'*wd
                

            # workaround: add explicit slicing to LDM/STM register_list fields
            if nm == "register_list" and wd == 13: nm = nm + "<12:0>"

            # if adjacent entries are two parts of same field, join them
            # e.g., imm8<7:1> and imm8<0> or opcode[5:2] and opcode[1:0]
            m = re.match('^(\w+)[<[]', nm)
            if m:
                nm = m.group(1)
                split = True
                if fields[-1][3] and fields[-1][2] == nm:
                    (hi1,lo1,_,_,c1) = fields.pop()
                    assert(lo1 == hi+1) # must be adjacent
                    hi = hi1
                    consts = c1+consts
            else:
                split = False

            # discard != information because it is better obtained elsewhere in spec
            if consts.startswith('!='): consts = 'x'*wd

            fields.append((hi,lo,nm,split,consts))

        # pad opcode with zeros for T16 so that all opcodes are 32 bits
        if isT16:
            fields.append((15,0,'_',False,'0'*16))

        # workaround: avoid use of overloaded field names
        fields2 = []
        for (hi, lo, nm, split, consts) in fields:
            if (nm in ["SP", "mask", "opcode"]
               and 'x' not in consts
               and exec.name not in ["aarch64/float/convert/fix", "aarch64/float/convert/int"]):
                # workaround: avoid use of overloaded field name
                nm = '_'
            fields2.append((hi,lo,nm,split,consts))

        dec_asl = readASL(iclass.find('ps_section/ps'))
        if decode: dec_asl.code = decode +"\n"+ dec_asl.code
        dec_asl.patchDependencies(names)
        dec_asl.patchTypeVar()

        name = dec_asl.name if insn_set in ["T16","T32","A32"] else encoding.attrib['psname']
        encs.append((name, insn_set, fields2, dec_asl))

    return (Instruction(exec.name, encs, post, conditional, exec), top)

########################################################################
# Reachability analysis
########################################################################

# Visit all nodes reachable from roots
# Returns topologically sorted list of reachable nodes
# and set of reachable nodes.
def reachable(graph, roots):
    visited = set()
    sorted = []

    def worker(seen, f):
        if f in seen:
            # print("Cyclic dependency",f)
            pass
        elif f not in visited:
            visited.add(f)
            deps = list(graph[f])
            deps.sort()
            for g in deps: worker(seen + [f], g)
            sorted.append(f)

    roots = list(roots)
    roots.sort()
    for f in roots: worker([], f)
    return (sorted, visited)

########################################################################
# Canary detection
########################################################################

# Check all paths from a function 'f' to any function in the list 'canaries'
# and report every such path.
# 'callers' is a reversed callgraph (from callees back to callers)
# Prints paths in reverse order (starting function first, root last) because that
# helps identify the common paths to the the starting function f
#
# Usage is to iterate over all canaries 'f' searching for paths that should not exist
def checkCanaries(callers, isChunk, roots, f, path):
    if f in path: # ignore recursion
        pass
    elif f in roots:
        path = [ g for g in path+[f] if not isChunk(g) ]
        print("  Canary "+" ".join(path))
    elif callers[f]:
        path = path + [f]
        for g in callers[f]:
            checkCanaries(callers, isChunk, roots, g, path)

########################################################################
# Main
########################################################################

def main():
    global alt_slice_syntax
    global include_regex
    global exclude_regex
    global demangle_instr

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--verbose', '-v', help='Use verbose output',
                        action = 'count', default=0)
    parser.add_argument('--altslicesyntax', help='Convert to alternative slice syntax',
                        action='store_true', default=False)
    parser.add_argument('--sail_asts', help='Output Sail file for AST clauses',
                        metavar='FILE', default=None)
    parser.add_argument('--demangle', help='Demangle instruction ASL',
                        action='store_true', default=False)
    parser.add_argument('--output', '-o', help='Basename for output files',
                        metavar='FILE', default='arch')
    parser.add_argument('dir', metavar='<dir>',  nargs='+',
                        help='input directories')
    parser.add_argument('--filter',  help='Optional input json file to filter definitions',
                        metavar='FILE', default=[], nargs='*')
    parser.add_argument(
        "--encoding",
        help="Optional list of architecture states to extract",
        choices=["T16", "T32", "A32"],
        default="T32",
    )

    parser.add_argument('--arch', help='Optional list of architecture states to extract',
                        choices=["AArch32", "AArch64"], default=[], action='append')
    parser.add_argument('--include', help='Regex to select instructions by name',
                        metavar='REGEX', default=None)
    parser.add_argument('--exclude', help='Regex to exclude instructions by name',
                        metavar='REGEX', default=None)
    args = parser.parse_args()

    alt_slice_syntax = args.altslicesyntax
    if args.include is not None:
        include_regex = re.compile(args.include)
    if args.exclude is not None:
        exclude_regex = re.compile(args.exclude)
    demangle_instr   = args.demangle

    encodings = []

    if "AArch32" in args.arch: encodings.extend(["T16", "T32", "A32"])
    if "AArch64" in args.arch: encodings.extend(["A64"])
    if args.verbose > 0:
        if encodings != []:
            print("Selecting encodings", ", ".join(encodings))
        else:
            print("Selecting entire architecture")

    notice = readNotice(ET.parse(os.path.join(args.dir[0], 'notice.xml')))
    (shared,names) = readShared([ f for d in args.dir for f in glob.glob(os.path.join(d, 'shared_pseudocode.xml'))])

    # reverse mapping of names back to the chunks containing them
    chunks = {}
    for a in shared.values():
        for d in a.defs:
            chunks[d] = a

    for a in shared.values():
        a.patchDependencies(chunks)

    decoder_files = [ 'encodingindex.xml', 't32_encindex.xml', 'a32_encindex.xml' ]
    decoders = [ readDecodeFile(d, f) for df in decoder_files for d in args.dir for f in glob.glob(os.path.join(d, df)) ]

    sailhack = args.sail_asts is not None
    instrs = []
    tops   = []
    for d in args.dir:
        for inf in glob.glob(os.path.join(d, '*.xml')):
            name = re.search('.*/(\S+).xml',inf).group(1)
            if name == "onebigfile": continue
            xml = ET.parse(inf)
            (instr, top) = readInstruction(xml,chunks,sailhack)
            if top: tops.append(top)
            if instr is None: continue
            instr.file_name = name

            if encodings != []: # discard encodings from unwanted InsnSets
                encs = [ e for e in instr.encs if e[1] in encodings ]
                if encs == []:
                    if args.verbose > 1: print("Discarding", instr.name, encodings)
                    continue
                instr.encs = encs
            instrs.append(instr)

    # Having read everything in, decide which parts to write
    # back out again and in what order

    if args.verbose > 3:
        for f in shared.values():
            print("Dependencies", f.name, "=", str(f.deps))
            print("Definitions", f.name, "=", str(f.defs))

    roots    = set()
    cuts     = set()
    canaries = set()
    for fn in args.filter:
        with open(fn, "r") as f:
            try:
                filter = json.load(f)
            except ValueError as err:
                print(err)
                sys.exit(1)
            for fun in filter['roots']:
                if fun not in chunks: print("Warning: unknown root", fun)
                roots.add(fun)
            for fun in filter['cuts']:
                if fun not in chunks: print("Warning: unknown cut", fun)
                cuts.add(fun)
            for fun in filter['canaries']:
                if fun not in chunks: print("Warning: unknown canary", fun)
                canaries.add(fun)

            # treat instrs as a list of rexexps
            patterns = [ re.compile(p) for p in filter['instructions'] ]
            instrs = [ i for i in instrs
                         if any(regex.match(i.name) for regex in patterns)
                     ]
            # print("\n".join(sorted([ i.name for i in instrs ])))
    # print("\n".join(sorted(chunks.keys())))

    # Replace all cutpoints with a stub so that we keep dependencies
    # on the argument/result types but drop the definition and any
    # dependencies on the definition.
    for x,s in shared.items():
        if any([d in cuts for d in s.defs]):
            if args.verbose > 0: print("Cutting", x)
            t = s.toPrototype()
            t.patchDependencies(chunks)
            # print("Cut", t)
            shared[x] = t

    # build bipartite graph consisting of chunk names and functions
    deps = defaultdict(set) # dependencies between functions
    for a in shared.values():
        deps[a.name] = a.deps
        for d in a.defs:
            deps[d] = {a.name}

    if args.verbose > 2:
        for f in deps: print("Dependency", f, "on", str(deps[f]))


    if encodings == [] and args.filter == []:
        # default: you get everything
        if args.verbose > 0: print("Keeping entire specification")
        roots |= { x for x in shared }
    else:
        if args.verbose > 0: print("Discarding definitions unreachable from",
                               ", ".join(encodings), " instructions")
        for i in instrs:
            for (_,_,_,dec) in i.encs: roots |= dec.deps
            if i.post: roots |= i.post.deps
            roots |= i.exec.deps
    (live, _) = reachable(deps, roots)

    # Check whether canaries can be reached from roots
    if canaries != set():
        if args.verbose > 0: print("Checking unreachability of", ", ".join(canaries))
        rcg = defaultdict(set) # reverse callgraph
        for f, ds in deps.items():
            for d in ds:
                rcg[d].add(f)
        for canary in canaries:
            if canary in live:
                checkCanaries(rcg, lambda x: x in shared, roots, canary, [])

    # print("Live:", " ".join(live))
    # print()
    # print("Shared", " ".join(shared.keys()))

    live_chunks = [ shared[x] for x in live if x in shared ]

    tagfile    = args.output + ".tag"
    instrfile  = args.output + "_instrs.asl"
    decodefile = args.output + "_decode.asl"
    aslfile    = args.output + ".asl"

    if args.verbose > 0: print("Writing instruction encodings to", tagfile)
    with open(tagfile, "w") as outf:
        emit(outf, 'notice:asl', notice)
        for i in instrs:
            i.emit_tag_syntax(outf)

    if args.verbose > 0: print("Writing instructions to", instrfile)
    with open(instrfile, "w") as outf:
        print(notice, file=outf)
        print(file=outf)
        for i in instrs:
            i.emit_asl_syntax(outf)
            print(file=outf)
        print('/'*72, file=outf)
        print('// End', file=outf)
        print('/'*72, file=outf)

    if args.verbose > 0: print("Writing instruction decoder to", decodefile)
    with open(decodefile, "w") as ofile:
        for (groups, classes) in decoders: printDecodeTree(ofile, groups, classes)

    if args.verbose > 0: print("Writing ASL definitions to", aslfile)
    with open(aslfile, "w") as outf:
        print(notice, file=outf)
        print(file=outf)
        print('\n'.join([ t for t in tops ]), file=outf)
        print('\n'.join([ x.code for x in live_chunks ]), file=outf)
        print('/'*72, file=outf)
        print('// End', file=outf)
        print('/'*72, file=outf)

    if args.sail_asts is not None:
        if args.verbose > 0: print("Writing Sail ast clauses to", args.sail_asts)
        with open(args.sail_asts, "w") as outf:
            print(notice, file=outf, end='\n\n')
            print('scattered union ast', file=outf, end='\n\n')
            previous_clauses = set()
            for i in instrs:
                i.emit_sail_ast(previous_clauses, outf)
            print('\nend ast', file=outf)

    
    return instrs



def generate_insts_from_asl(instrs, output, inst_mode):
    with open(output,"w") as f:
        for i in instrs:
            i.emit_insts(f,inst_mode)



def generate_specific_insts(instrs,inst_mode,inst_name):
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != inst_mode:
                continue
            if inst_name != inm:
                continue
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            instencoding.generate_insts()
            print(inm)
 


def cover_constraint(instrs,input_file,inst_set):
    f = open(input_file,"r")
    lines = f.readlines()
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != inst_set:
                continue
            if inm not in valid_insts:
                continue
            instencoding = InstEncoding(inm,fields,dec,i.exec)
            instencoding.generate_insts()
            all_insts = valid_insts[inm]
            inst_covered_constraints = instencoding.covered_constraints(all_insts)
            all_rand_constraints[inm] = inst_covered_constraints

    print(all_rand_constraints)


def random_valid_insts(instrs,input_file,output_file,inst_set):
    f = open(input_file,"r")
    lines = f.readlines()
    f.close()
    f_v = open(output_file,"w")
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != inst_set:
                continue
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            for l in lines:
                if instencoding.isThisEncoding(l.strip()):
                    f_v.write("%s %s\n"%(inm, l.strip()))
                    print("identified %s %s\n"%(inm, l.strip()))
                    lines.remove(l)
    f_v.close()               

def generate_random_insts(number,output_file,inst_set):
    value = ["0","1"]
    f = open(output_file,"w")
    sample_num = number
    results = set()
    while(True):
        b = ""
        for j in range(32):
            bit = random.sample(value,1)[0]
            b += bit
        if inst_set == "T16":
            b = b[:16]+"0"*16
        results.add(b)
        if len(results) % 100 == 0:
            print("generate %d samples"%len(results))
        if len(results) == sample_num:
            break 
    for b in list(results):
        f.write("%s\n"%b)
    f.close()

def random_covered_constraints(instrs,input_file,output_file,target_set):
    valid_insts = {}
    f = open(input_file)
    lines = f.readlines()
    f.close()
    for l in lines:
        if l.strip() == "":
            continue 
        encoding = l.split(" ")[0].strip()
        inst = l.split(" ")[1].strip()
        if encoding not in valid_insts:
            valid_insts[encoding] = []
        valid_insts[encoding].append(inst)

    all_rand_constraints = {}

    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != target_set:
                continue
            if inm not in valid_insts:
                continue
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            instencoding.generate_insts()
            all_insts = valid_insts[inm]
            inst_covered_constraints = instencoding.covered_constraints(all_insts)
            all_rand_constraints[inm] = inst_covered_constraints

    with open(output_file, "w") as output_f:
        json.dump(all_rand_constraints, output_f, indent=4)


def filter_orig_a32(instrs,input_file,output_file,target_set):
    f = open(input_file,'r')
    lines = f.readlines()
    f.close()
    f = open(output_file,"w")
    all_instencodings = {}
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            all_instencodings[deslash(inm)+"_"+insn_set] = instencoding
    for l in lines:
        encoding = l.split(" ")[0].strip()
        inst_set = l.split(" ")[1].strip()
        inst = l.split(" ")[2].strip()
        if inst_set != target_set:
            continue
        if  all_instencodings[encoding+"_"+inst_set].isThisEncoding(inst):
            f.write("%s %s %s\n"%(encoding,inst_set,inst))
            print("%s %s %s\n"%(encoding,inst_set,inst))
    f.close()
    #print(all_instencodings["aarch32_VQSHL_r_T1A1_A_A32"].isThisEncoding("11110010000000000101010010111101"))





def patch():

    # Loop the Instructions 

    """
    a64_f = open("/mnt/muhui/ins_emu/a64_new_test.txt","r")
    lines = a64_f.readlines()
    a64_f.close()
    a64_insts = {}
    for line in lines:
        name = line.strip().split(" ")[0]
        inst = line.strip().split(" ")[2]
        a64_insts[inst]= name
            
    print(len(a64_insts.keys()))
    sys.exit()

    new_results = {}
    
    inst_dic = {}
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            inm = deslash(inm)
            if insn_set != "A64":
                continue
            if inm not in inst_dic:
                inst_dic[inm] = []
            print(inm)
            inst_dic[inm].append(InstEncoding(inm+"_"+i.file_name,fields,dec,i.exec))


    index = 0
    for l in a64_insts:
        index = index+1
        if index %1000 == 0:
            print("finish %d insts"%index)
        flag = False
        for instencoding in inst_dic[a64_insts[l]]:
            if instencoding.isThisEncoding(l.strip()):
                #print("% should be %s %s\n"%(l, inm+instencoding.file_name))
                new_results[l] = instencoding.name
                flag = True
                break
        if flag == False:
            print("cannot find valid encoding for %s %s"%(l,a64_insts[l]))

    """
    f = open("a64_patch.txt","r")

    lines = f.readlines()
    
    f.close()
    p_insts = {}
    for line in lines:
        name = line.strip().split(" ")[0]
        inst = line.strip().split(" ")[2]
        p_insts[inst]= name


    a64_f = open("/mnt/muhui/ins_emu/a64_new_test.txt","r")
    a64_f_p = open("/mnt/muhui/ins_emu/a64_new_test_patch.txt","w")
    lines = a64_f.readlines()
    a64_f.close()
    for line in lines:
        name = line.strip().split(" ")[0]
        inst = line.strip().split(" ")[2]
        a64_f_p.write("%s A64 %s\n"%(p_insts[inst],inst))

    a64_f_p.close()

    #with open("arm7_arm.json") as f:
    #    result = json.load(f)

    #all_rand_constraints = {}
    """
    all_valid_insts = {}

    all_unpredicatables = {}
    all_encodings = {}
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != "A64":
                continue
            #if inm not in valid_insts:
            #    continue
            instencoding = InstEncoding(inm,fields,dec,i.exec)
            instencoding.generate_insts()
            #instencoding.unpredicatableConditions(dec.code)
            all_encodings[deslash(inm)] = instencoding
    
    print(all_encodings)
    with open("bin/aarch64.json") as f:
        result = json.load(f)
        for k in result:
            if k == "both":
                for t in result["both"]:
                    for encoding in result["both"][t]:
                        for case in result["both"][t][encoding]["testcases"]:
                            if all_encodings[encoding].isUnpredictable(bin(int('0x'+case["machine_code"],16))[2:]):
                                all_unpredicatables[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]

            else:
                for encoding in result[k]:
                    for case in result[k][encoding]["testcases"]:
                        if all_encodings[encoding].isUnpredictable(bin(int('0x'+case["machine_code"],16))[2:]):
                            all_unpredicatables[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]
                        #all_valid_insts[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]


    print(all_unpredicatables)
    with open("aarch64_unpredictable.json","w") as outfile:
        json.dump(all_unpredicatables,outfile,indent = 4)

    """

    """
    valid_insts = []
    f = open("bin/t32_rand.txt")
    lines = f.readlines()
    f.close()
    f_v = open("bin/t32_rand_valid.txt","w")
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != "T32":
                continue
            instencoding = InstEncoding(inm,fields,dec,i.exec)
            for l in lines:
                if instencoding.isThisEncoding(l.strip()):
                    f_v.write("%s %s\n"%(inm, l.strip()))
                    print("identified %s %s\n"%(inm, l.strip()))
                    lines.remove(l)
    f_v.close()               


    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            print(inm)
            for l in dec.code.split("\n"):
                if "UNDEFINED" in l:
                    print (l)
            for l in i.exec.code.split("\n"):
                if "UNDEFINED" in l:
                    print (l)

    valid_insts = {}
    f = open("bin/t32_rand_valid.txt")
    lines = f.readlines()
    f.close()
    for l in lines:
        if l.strip() == "":
            continue 
        encoding = l.split(" ")[0].strip()
        inst = l.split(" ")[1].strip()
        if encoding not in valid_insts:
            valid_insts[encoding] = []
        valid_insts[encoding].append(inst)

    all_rand_constraints = {}

    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != "T32":
                continue
            if inm not in valid_insts:
                continue
            instencoding = InstEncoding(inm,fields,dec,i.exec)
            instencoding.generate_insts()
            all_insts = valid_insts[inm]
            inst_covered_constraints = instencoding.covered_constraints(all_insts)
            all_rand_constraints[inm] = inst_covered_constraints

    print(all_rand_constraints)

    with open("bin/t32_rand_valid_constraint.json", "w") as outfile:
        json.dump(all_rand_constraints, outfile, indent=4)

    for f in fail_solved_constraint:
        print(f)
    return
    """


def generate_a32_random_all(instrs,index):
    generate_random_insts(870221,"bin/a32_rand.txt"+str(index),"A32")
    random_valid_insts(instrs,"bin/a32_rand.txt"+str(index),"bin/a32_rand_valid.txt"+str(index),"A32")
    random_covered_constraints(instrs,"bin/a32_rand_valid.txt"+str(index),"bin/a32_rand_valid_constraint.json"+str(index),"A32")
    
    print("finish %d A32"%index)
    generate_random_insts(808770,"bin/t32_rand.txt"+str(index),"T32")
    random_valid_insts(instrs,"bin/t32_rand.txt"+str(index),"bin/t32_rand_valid.txt"+str(index),"T32")
    random_covered_constraints(instrs,"bin/t32_rand_valid.txt"+str(index),"bin/t32_rand_valid_constraint.json"+str(index),"T32")

    print("finish %d T32"%index)

    generate_random_insts(958,"bin/t16_rand.txt"+str(index),"T16")
    random_valid_insts(instrs,"bin/t16_rand.txt"+str(index),"bin/t16_rand_valid.txt"+str(index),"T16")
    random_covered_constraints(instrs,"bin/t16_rand_valid.txt"+str(index),"bin/t16_rand_valid_constraint.json"+str(index),"T16")

    print("finish %d T16"%index)
            

    #generate_random_insts(1094700,"bin/a64_rand.txt","A64")
    #random_valid_insts(instrs,"bin/a64_rand.txt","bin/a64_rand_valid.txt","A64")
    #random_covered_constraints(instrs,"bin/a64_rand_valid.txt","bin/a64_rand_valid_constraint.json","A64"):
 
def generate_a64_random_all(instrs,index):
    generate_random_insts(1094700,"bin/a64_rand.txt"+str(index),"A64")
    random_valid_insts(instrs,"bin/a64_rand.txt"+str(index),"bin/a64_rand_valid.txt"+str(index),"A64")
    random_covered_constraints(instrs,"bin/a64_rand_valid.txt"+str(index),"bin/a64_rand_valid_constraint.json"+str(index),"A64")

def calculate_random():
    results = {}
    for valid in ["a32","t32","t16","a64"]:
        if valid not in results:
            results[valid] = {}
        print(valid)
        number = []
        cover_encoding = []
        cover_instruction = []
        cover_constraint  = []
        for i in range(10):
            if i not in results[valid]:
                results[valid][i] = {}
            valid_file = "bin/%s_rand_valid.txt%d"%(valid,i)
            with open(valid_file,"r") as f:
                lines = f.readlines()
                results[valid][i]["number"] = len(lines)
            print(valid_file)
            valid_constraint_file = "bin/%s_rand_valid_constraint.json%d"%(valid,i)
            tmp = set()
            with open(valid_constraint_file,"r") as f:
                constraint_file_data = json.load(f)
                results[valid][i]["cover_encoding"] = len(constraint_file_data.keys())
                results[valid][i]["cover_constraint"] = str(constraint_file_data).count("True")
                for k in constraint_file_data:
                    tmp.add(k.split("/")[1])

            number.append(results[valid][i]["number"])
            cover_encoding.append(results[valid][i]["cover_encoding"])
            cover_constraint.append(results[valid][i]["cover_constraint"])
            cover_instruction.append(len(tmp))



        print("number:")
        print(max(number))
        print(min(number))
        print(sum(number)/len(number))

        print("cover_encoding:")
        print(max(cover_encoding))
        print(min(cover_encoding))
        print(sum(cover_encoding)/len(cover_encoding))


        print("cover_constraint")
        print(max(cover_constraint))
        print(min(cover_constraint))
        print(sum(cover_constraint)/len(cover_constraint))



        print("cover_instruction")
        print(max(cover_instruction))
        print(min(cover_instruction))
        print(sum(cover_instruction)/len(cover_instruction))

    return results





def tests_covered_constraints(instrs,input_file,output_file,target_set):
    valid_insts = {}
    f = open(input_file)
    lines = f.readlines()
    f.close()
    for l in lines:
        if l.strip() == "":
            continue 
        encoding = l.split(" ")[0].strip()
        inst = l.split(" ")[2].strip()
        if encoding not in valid_insts:
            valid_insts[encoding] = []
        valid_insts[encoding].append(inst)

    print(valid_insts.keys())
    all_rand_constraints = {}

    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            inm = deslash(inm)+"_"+i.file_name
            if insn_set != target_set:
                continue
            if inm not in valid_insts:
                print(inm)
                continue
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            instencoding.generate_insts()
            all_insts = valid_insts[inm]
            inst_covered_constraints = instencoding.covered_constraints(all_insts)
            all_rand_constraints[inm] = inst_covered_constraints

    with open(output_file, "w") as output_f:
        json.dump(all_rand_constraints, output_f, indent=4)

def filter_unpredictables(instrs,input_file,output_file,mode):

    all_unpredicatables = {}
    all_encodings = {}
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set != mode:
                continue
            #if inm not in valid_insts:
            #    continue
            instencoding = InstEncoding(inm,i.post,fields,dec,i.exec)
            instencoding.generate_insts()
            #instencoding.unpredicatableConditions(dec.code)
            all_encodings[deslash(inm)] = instencoding
    
    print(all_encodings)
    with open(input_file) as f:
        result = json.load(f)
        for k in result:
            if k == "both":
                for t in result["both"]:
                    for encoding in result["both"][t]:
                        for case in result["both"][t][encoding]["testcases"]:
                            if all_encodings[encoding].isUnpredictable(bin(int('0x'+case["machine_code"],16))[2:]):
                                all_unpredicatables[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]

            else:
                for encoding in result[k]:
                    for case in result[k][encoding]["testcases"]:
                        if all_encodings[encoding].isUnpredictable(bin(int('0x'+case["machine_code"],16))[2:]):
                            all_unpredicatables[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]
                        #all_valid_insts[case["id"]] = bin(int('0x'+case["machine_code"],16))[2:]


    print(all_unpredicatables)
    with open(output_file,"w") as outfile:
        json.dump(all_unpredicatables,outfile,indent = 4)




if __name__ == "__main__":
    instrs = main()
    tmp = 0
    for i in instrs:
        for (inm, insn_set, fields, dec) in i.encs:
            if insn_set == "T32" or insn_set == "T16":
                tmp += 1
                break
    print(tmp)
    #generate_a32_random_all(instrs)
    #filter_orig_a32(instrs,"bin/a32_orig_test.txt","bin/t16_filter_test.txt","T16")

    #tests_covered_constraints(instrs,"bin/a64_filter_test.txt","bin/a64_tmp.json","A64")
    #filter_unpredictables(instrs,"bin/arm6_arm.json","bin/arm6_arm_filter.json","A32")
    
    #start = time.time()
    #generate_insts_from_asl(instrs, "a32_tmp.txt", "A64")
    #print(time.time() - start)
    #generate_specific_insts(instrs,"A32","aarch32/VLD4_m/T1A1_A")
    #results = calculate_random()
    #print(results)

  

    print(all_constraint)
    print(all_valid_constraint)
    print(all_solved_constraint)
   #print(all_valid_constraint)
    #print(all_solved_constraint)
########################################################################
# End
########################################################################
