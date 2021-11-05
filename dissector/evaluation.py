# import sys
# from config import QUIET, VERBOSE, DEBUG, LOGGER
#
#
# def evaluate_fingerprint(df, df_fingerprint, fingerprints):
#     """
#     :param df: datafram itself
#     :param df_fingerprint: dataframe filtered based on matched fingerprint
#     :param fingerprints: dictionary with fingerprint(s)
#     :return accuracy_ratio: the percentage that generated fingerprint can match in the full dataframe
#     """
#
#     msg = "Fingerprint evaluation"
#     sys.stdout.write('\r' + '[' + '\u2713' + '] ' + msg + '\n')
#
#     LOGGER.info("TRAFFIC MATCHED: {0}%. The generated fingerprint will filter {0}% of the analysed traffic".format(
#         round(len(df_fingerprint) * 100 / len(df))))
#     percentage_of_ips_matched = len(df_fingerprint['ip_src'].unique().tolist()) * 100 / len(df.ip_src.unique().tolist())
#     LOGGER.info("IPS MATCHED    : {0}%. The generated fingerprint will filter {0}% of SRC_IPs".format(
#         round(percentage_of_ips_matched)))
#
#     if not QUIET:
#         value = round(len(df_fingerprint) * 100 / len(df))
#         print_progress_bar(value, "TRAFFIC MATCHED")
#         print_progress_bar(round(percentage_of_ips_matched), "IPs MATCHED")
#     #
#     # Fields breakdown
#     #
#     if verbose or debug:
#
#         count = 0
#
#         try:
#             df.fragmentation = df.fragmentation.astype(str, errors='ignore')
#         except AttributeError:
#             pass
#
#         # for each fingerprint generated
#         for fingerprint in (fingerprints['attack_vector']):
#             count = count + 1
#             results = {}
#             for key, value in fingerprint.items():
#
#                 if key in ["src_ips", "attack_vector_key", "one_line_fingerprint"]:
#                     continue
#                 val = ','.join(str(v) for v in value)
#                 val = val.split()
#                 total_rows_matched = len(df[df[key].isin(val)])
#                 percentage = round(total_rows_matched * 100 / len(df))
#
#                 # dict with all the fields and results
#                 results.update({key: percentage})
#             results_sorted = {k: v for k, v in sorted(results.items(), key=lambda item: item[1], reverse=True)}
#
#             LOGGER.info(" ============= FIELDS BREAKDOWN === ATTACK_VECTOR {} ============= ".format(count))
#             for label, percentage in results_sorted.items():
#                 print_progress_bar(percentage, label, "▭ ")
#
#     return
