import json

def report_to_console(year, report, clusters, unsolved_clusters):
    total_entrys = report.get("total_entrys")
    unique_entrys = report.get("unique_entrys")
    non_unique_entrys = report.get("non_unique_entrys")

    # Before algorithm
    cve_uniqueness_score = 100 * (len(unique_entrys) / len(total_entrys))
    print("Total CVEs in " , year, ": " ,len(total_entrys))
    print("  -Before applying algorithm: ")
    print("     Percentage of unique combinations:", round(cve_uniqueness_score, 2), "%")
    print("     CVEs with unique combination of cwe and cpe:", len(unique_entrys))
    print("     CVEs with non unique combination of cwe and cpe:", len(non_unique_entrys))
    print("        Number of clusters:", len(clusters))
    print("         - Length between 1 and 5:", len(sort_clusters(clusters, 1, 5)))
    print("         - Length between 6 and 10:", len(sort_clusters(clusters, 6, 10)))
    print("         - Length between 11 and 50:", len(sort_clusters(clusters, 11, 50)))
    print("         - Length between 51 and 500:", len(sort_clusters(clusters, 51, 500)))
    print("         - Length > 500:", len(clusters) - len(sort_clusters(clusters, 1, 500)))
    print("         - Average amount of entrys in a cluster:", round(len(non_unique_entrys)/len(clusters), 2))
    
    # After algorithm
    non_unique_entrys = get_nonunique_amount(unsolved_clusters)
    unique_entrys = len(total_entrys) - non_unique_entrys
    cve_uniqueness_score = 100 * (unique_entrys / len(total_entrys))
    print("  -After applying algorithm: ")
    print("     Percentage of unique combinations:", round(cve_uniqueness_score, 2), "%")
    print("     CVEs with unique combination of cwe and cpe:", unique_entrys)
    print("     CVEs with non unique combination of cwe and cpe:", non_unique_entrys)

def cluster_analysis_to_file(clusters, year, file_name, description):
    index = 0
    text_file = open(file_name, "w")
    n = text_file.write(description)
    for cluster in clusters:
        string = "-Cluster " + str(index) + ":\n"
        text_file.write(string)
        string_length = "   -Number of entries: " + str(len(cluster)) + " \n"
        text_file.write(string_length)
        text_file.write("   -cwe-cpe-combination: \n")
        text_file.write("    ")
        cwe_cpe_combination = get_cwe_cpe_combination(cluster[0])
        json.dump(cwe_cpe_combination, text_file, indent=4)
        text_file.write("\n   -Descriptions: \n")
        for entry in cluster:
            text_file.write("     -")
            text_file.write(entry.get("description")[0])
            text_file.write("\n")
        index = index +1
        text_file.write("\n")
    text_file.close()

def write_clusters_to_file(clusters, year):
    file_name = "src/cluster/clusters_" + str(year) + ".json"
    with open(file_name, 'w') as outfile:
        #json_data = json.dumps(clusters, indent=4)
        json.dump(clusters, outfile, indent=4)
    print("Finished printing clusters to file for year: ", str(year))

def get_cwe_cpe_combination(cve):
    cwe_cpe_combination = {
            "cwe": cve.get("cwe"),
            "cpe": cve.get("cpe")
    }
    return cwe_cpe_combination

def sort_clusters(clusters, minLength, maxLength):
    sorted_clusters = []
    for cluster in clusters:
        cluster_length = len(clusters.get(cluster))
        if cluster_length >= minLength and cluster_length <= maxLength:
            sorted_clusters.append(clusters.get(cluster))
    return sorted_clusters

def get_nonunique_amount(unsolved_clusters):
    amount = 0
    for cluster in unsolved_clusters:
        amount = amount + len(cluster)
    return amount
