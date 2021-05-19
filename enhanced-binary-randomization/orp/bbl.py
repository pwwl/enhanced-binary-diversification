# Copyright (c) 2012, Vasilis Pappas <vpappas@cs.columbia.edu>
# This file is part of Orp http://nsl.cs.columbia.edu/projects/orp

# Additionally modified by Mahmood Sharif <mahmoods@alumni.cmu.edu>
# Alternate contact is Keane Lucas <keanelucas@cmu.edu>

class BasicBlock:

  NORMAL = 0
  ENTRY  = 1
  EXIT   = 2

  def __init__(self, begin, end, code):
    self.begin = begin
    self.end = end
    self.instrs = [i for a, i in code.iteritems() if a >= begin and a <= end]
    self.instrs.sort(key=lambda x: x.addr)
    self.successors = []
    self.type = BasicBlock.NORMAL
    if len(self.instrs) == 0: #it's always 0 now .. FIXME
      return
    if self.instrs[0].f_entry:
      self.type |= BasicBlock.ENTRY
    if self.instrs[-1].f_exit:
      self.type |= BasicBlock.EXIT

  def reschedule(self):
    pass

  def __repr__(self):
    return "0x%08X : 0x%08X" % (self.begin, self.end)

