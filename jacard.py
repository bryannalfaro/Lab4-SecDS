import os, networkx, itertools
import matplotlib.pyplot as plt

def jaccard(set1,set2):
    intersection = set1.intersection(set2)
    intersection_length = float(len(intersection))
    union = set1.union(set2)
    union_length = float(len(union))
    return intersection_length / union_length

def getstrings(fullpath):
    strings = os.popen("strings '{0}'".format(fullpath)).read()
    strings = set(strings.split("\n"))
    return strings

def run_jacard():
  malware_path = './MALWR'
  threshold = 0.8

  malware_paths = [] # where we'll store the malware file paths
  malware_attributes = dict() # where we'll store the malware strings
  graph = networkx.Graph() # the similarity graph

  for root, dirs, paths in os.walk(malware_path):
      for path in paths:
          full_path = os.path.join(root,path)
          malware_paths.append(full_path)

  for path in malware_paths:
      attributes = getstrings(path)
      print ("Extracted {0} attributes from {1} ...".format(len(attributes),path))
      malware_attributes[path] = attributes

      graph.add_node(path,label=os.path.split(path)[-1][:10])

  for malware1,malware2 in itertools.combinations(malware_paths,2):

      jaccard_index = jaccard(malware_attributes[malware1],malware_attributes[malware2])

      if jaccard_index > threshold:
          print (malware1,malware2,jaccard_index)
          graph.add_edge(malware1,malware2,penwidth=1+(jaccard_index-threshold)*10)

  networkx.draw(graph)
  plt.show() 