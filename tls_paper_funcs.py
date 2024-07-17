import numpy as np
import pandas as pd

# Feed TLS 1.3 only. Full row, with tls_dir, tls_b, tls_tp
def cert_size_inference_simple_diagram(curr_row_13, row_id=0):
    """
    Performs certificate size inference on a single dataframe row.
    Only TLS 1.3 rows should be provided (each w/ 20 tls_dir, tls_b and tls_tp columns).
    """
    tls_tps = ['tls_tp_'+str(x) for x in range(20)]
    tls_bs = ['tls_b_'+str(x) for x in range(20)]
    tls_dir = ['tls_dir_'+str(x) for x in range(20)]

    tls_dir_values_13 = curr_row_13[tls_dir].values
    tls_b_values_13 = curr_row_13[tls_bs].values
    tls_tp_values_13 = curr_row_13[tls_tps].values
    
    ## Discard handshake
    first_cli_appdata = -1
    for i in range(len(tls_dir_values_13)):
        if (tls_dir_values_13[i] == 0) and (tls_tp_values_13[i] == 23):
            first_cli_appdata = i # This is the client "finished"
            break
    if first_cli_appdata == -1:
        # no app data C2S (no success confirmation). throw error?
        return -1
    
    intermediate_records = [a for a, b, c in zip(tls_b_values_13[:first_cli_appdata], 
                                              tls_dir_values_13[:first_cli_appdata],
                                              tls_tp_values_13[:first_cli_appdata]) if (b == 1) and (c == 23)]
    
    if len(intermediate_records) == 0:
        print("no int records", first_cli_appdata, row_id)
        return -1
    
    if len(intermediate_records) == 1:
        # One single "Multiple Handshake Messages" with extensions, certificate, certificate verify and finished.
        # Discounting the extra bytes (an approximate, plausible value) -- ~149 or ~335 bytes
        guess = intermediate_records[0]-149
    else:
        # Either one individual record for each handshake message (and certificate is in second or in third to last)
        # Or a "multiple handshake messages" fragmented into multiple records -- same as above, but need to sum all fragments
        if intermediate_records[0] > 300:
            # multiple messages fragmented
            guess = sum(intermediate_records)-149+17-len(intermediate_records)*17 #149 already includes one "17"
        else:
            # Probably one record for each message, but perhaps a fragmented certificate
            
            # Consider only until the Finished message (size 53 or 69), discard what comes after (new session ticket?)
            if 69 in intermediate_records:
                intermediate_records = intermediate_records[:intermediate_records.index(69)]
            elif 53 in intermediate_records:
                intermediate_records = intermediate_records[:intermediate_records.index(53)]
            
            if len(intermediate_records) <= 3:
                guess = max(intermediate_records)-8-17 # no fragmented certificate
            else:
                guess = sum(intermediate_records[1:-1])-8-len(intermediate_records[1:-1])*17 # fragmented certificate
    return guess

# Feed TLS 1.3 only. Full row, with tls_dir, tls_b, tls_tp
# First, filter for tp == 23
def nst_detection_and_removal_after_filtering(curr_row_13, remove_trailing_19 = True, subtract_17 = False, return_series = False):
    tls_dir = ['tls_dir_'+str(x) for x in range(20)]
    tls_bs = ['tls_b_'+str(x) for x in range(20)]
    
    tls_dir_values_13 = curr_row_13[tls_dir].values
    tls_b_values_13 = curr_row_13[tls_bs].values
    #tls_tp_values_13 = curr_row_13[tls_tps].values
        
    ## Discard handshake
    discard_until = -1
    for i in range(len(tls_dir_values_13)):
        if tls_dir_values_13[i] == 0:
            discard_until = i # This is the client "finished"
            break
    if discard_until == -1:
        # no app data C2S (no success confirmation). throw error?
        return [],[]
    tls_dir_values_13 = np.array(tls_dir_values_13[discard_until+1:]) # to account for self
    tls_b_values_13 = np.array(tls_b_values_13[discard_until+1:])
    #tls_tp_values_13 = np.array(tls_tp_values_13[discard_until+1:])
    ## Discard handshake
    
    tls_dir_values_13 = tls_dir_values_13[tls_dir_values_13 != -1]
    tls_b_values_13 = tls_b_values_13[tls_b_values_13 != -1]
    #tls_tp_values_13 = tls_tp_values_13[tls_tp_values_13 != -1]
    
    if len(tls_b_values_13) == 0:
        # empty after removing handshake
        return [],[]
    
    # Remove trailing 19
    if remove_trailing_19:
        #if tls_b_values_13[-1] == 19:
        # Look for a Finished in each direction:
        replace_index = np.where((tls_b_values_13==19) & (tls_dir_values_13==0))[0]
        if len(replace_index):
            tls_dir_values_13 = np.concatenate([tls_dir_values_13[:replace_index.max()],
                                                tls_dir_values_13[replace_index.max()+1:]])
            tls_b_values_13 = np.concatenate([tls_b_values_13[:replace_index.max()],
                                              tls_b_values_13[replace_index.max()+1:]])
            #tls_tp_values_13 = np.concatenate([tls_tp_values_13[:replace_index.max()],
            #                                   tls_tp_values_13[replace_index.max()+1:]])
        else:
            replace_index = np.where( (tls_b_values_13==19) & (tls_dir_values_13==1))[0]
            if len(replace_index):
                tls_dir_values_13 = np.concatenate([tls_dir_values_13[:replace_index.max()],
                                                    tls_dir_values_13[replace_index.max()+1:]])
                tls_b_values_13 = np.concatenate([tls_b_values_13[:replace_index.max()],
                                                  tls_b_values_13[replace_index.max()+1:]])
                #tls_tp_values_13 = np.concatenate([tls_tp_values_13[:replace_index.max()],
                #                                   tls_tp_values_13[replace_index.max()+1:]])
    
    # Subtract 17? We won't generaly discard the 17 bytes of overhead,
    # because TLS 1.2 also added its own overhead (>20bytes, ~25).
    if subtract_17:
        tls_b_values_13 = tls_b_values_13 - 17
    
    #print(tls_dir_values_13, tls_b_values_13, tls_tp_values_13)
    
    firstC2S = -1
    for i in range(len(tls_dir_values_13)): # look for first app data C2S
        if tls_dir_values_13[i] == 0:
            firstC2S = i
            break
    if firstC2S == -1:
        #return [],[],[] # No C2S found (besides finished -- strange behavior)
        return tls_b_values_13, tls_dir_values_13
    secondC2S = -1
    
    # if there are 2 consecutive c2s, we won't be sure if the s2c will just be two
    # replies. in that case, perhaps we shouldn't look for NST.
    if len(tls_dir_values_13) >= firstC2S+2:
        if tls_dir_values_13[firstC2S+1] == 0:
            consecutive_c2s = True
            # consecutive C2S, do not look for NST
        else:
            consecutive_c2s = False
    else:
        consecutive_c2s = False
        # since the firstC2S+1 is S2C, look for another C2S:
        for i in range(firstC2S+2, len(tls_dir_values_13)):
            if tls_dir_values_13[i] == 0:
                secondC2S = i
                break
    if secondC2S == -1: # there is no second request -- one req, one response
        # consider all records
        secondC2S = len(tls_dir_values_13)
    
    #print(firstC2S, secondC2S, len(tls_dir_values_13))
    # look for NST in S2C records until the second client request:
    int_records_ind = [(a,c) for a, b, c in zip(list(tls_b_values_13[:secondC2S]), 
                                                list(tls_dir_values_13[:secondC2S]),
                                                list(range(secondC2S)) )
                             if (b == 1)]
    int_records = [a for a,b in int_records_ind]
    
    if len(int_records) == 0:
        #print( list(tls_b_values_13[:secondC2S]),
        #       list(tls_dir_values_13[:secondC2S]) )
        # No server response at all?
        return tls_b_values_13, tls_dir_values_13
    
    if int_records_ind[0][1] < firstC2S:
        # a response even before a request -- most likely NST
        # but perhaps not.
        if (int_records[0] > 600) or (int_records[0] < 100):
            # if the size of the response doesn't match an NST,
            # just ignore.
            return tls_b_values_13, tls_dir_values_13
        nst_size = int_records[0]
        # exclude int_records of size nst_size
        indices_to_remove = [b for a,b in int_records_ind if a == nst_size]
        return [tls_b_values_13[i] for i in range(len(tls_b_values_13)) if i not in indices_to_remove], \
               [tls_dir_values_13[i] for i in range(len(tls_dir_values_13)) if i not in indices_to_remove]
    
    if len(int_records) < 2:
        # One response to one request, cannot be sure, probably no NST
        return tls_b_values_13, tls_dir_values_13
    elif len(int_records) == 2:
        # discard first
        # in the unlikely even that the two are equal, we exclude both
        # unless they are the only server response -- sending only NST and closing would be atypical
        if consecutive_c2s:
            # Not sure, could be two replies
            return tls_b_values_13, tls_dir_values_13
        elif (int_records[0] == int_records[1]) and (secondC2S != len(tls_dir_values_13)):
            # Both excluded -- making sure it is not the only request/response
            return list(tls_b_values_13[:int_records_ind[0][1]]) + list(tls_b_values_13[int_records_ind[1][1]+1:]), \
                   list(tls_dir_values_13[:int_records_ind[0][1]]) + list(tls_dir_values_13[int_records_ind[1][1]+1:])
        else:
            # Only first one excluded
            return list(tls_b_values_13[:int_records_ind[0][1]]) + list(tls_b_values_13[int_records_ind[0][1]+1:]), \
                   list(tls_dir_values_13[:int_records_ind[0][1]]) + list(tls_dir_values_13[int_records_ind[0][1]+1:])
    else:
        # more than two responses to the first request
        # mark the first as NST, and the next ones of the same size 
        # unless the first one is too large or too small (not common for NST)
        if (int_records[0] > 600) or (int_records[0] < 100):
            return tls_b_values_13, tls_dir_values_13
        
        # choose the first one
        nst_size = int_records[0]
        
        # else: choose the one with the most repetitions -- this would only work
        # if we ignore the client requests, and look only at server responses, but
        # can we be sure that a repeated, same size response is necessarily an NST?
        #values, counts = np.unique(int_records, return_counts=True)
        #ind = np.argmax(counts)
        #if (np.max(counts) > 1) and (values[ind] < 1000) and (values[ind] > 60):
        #    nst_size = values[ind]
        
        # exclude int_records of size nst_size
        indices_to_remove = [b for a,b in int_records_ind if a == nst_size]
        
        # instead of excluding int_records, we should exclude all consecutive records:
        
        
        nst_discard_b, nst_discard_dir = \
               [tls_b_values_13[i] for i in range(len(tls_b_values_13)) if i not in indices_to_remove], \
               [tls_dir_values_13[i] for i in range(len(tls_dir_values_13)) if i not in indices_to_remove]
        
        return nst_discard_b, nst_discard_dir

def handshake_removal_only(curr_row_13, remove_trailing_19 = True, subtract_17 = False):
    """
    Removes the presumable Handshake-related messages from whithin Application Data records,
    leaving behind those that are "true" application data.

    The name of the function might be a little misleading: the function attempts to remove
    New Session Tickets too; the "only" is opposed to a previous function that also used
    to filter for type 23 (0x17) records, which this one does not do.
    This function assumes that you feed it a TLS 1.3 flow, previously filtered for records
    of type 23 (0x17).
    """
    tls_dir = ['tls_dir_'+str(x) for x in range(20)]
    tls_bs = ['tls_b_'+str(x) for x in range(20)]
    
    tls_dir_values_13 = curr_row_13[tls_dir].values
    tls_b_values_13 = curr_row_13[tls_bs].values
        
    ## Discard handshake
    discard_until = -1
    for i in range(len(tls_dir_values_13)):
        if tls_dir_values_13[i] == 0:
            discard_until = i # This is the client "finished"
            break
    if discard_until == -1:
        # no app data C2S (no success confirmation). throw error?
        return [],[]
    
    finished_message_size = tls_b_values_13[discard_until]
    # server finished before client finished:
    server_finished_messages = [a for a in np.where((tls_b_values_13 == finished_message_size) & (tls_dir_values_13==1))[0] if a < discard_until]
    if len(server_finished_messages):
        discard_until_s2c = np.max(server_finished_messages)
        bs_and_dirs = [(b_val, dir_val) for a,(b_val, dir_val) in 
                       enumerate(zip(tls_b_values_13, tls_dir_values_13))
                       if ((dir_val == 0) and (a > discard_until)) or ((dir_val == 1) and (a > discard_until_s2c))]
        if len(bs_and_dirs):
            b_vals, dir_vals = zip(*bs_and_dirs)
            tls_b_values_13 = np.array(b_vals)
            tls_dir_values_13 = np.array(dir_vals)
        else:
            return [],[]
    else:
        # if we didn't find a server finished, discard everything until client finished.
        tls_dir_values_13 = np.array(tls_dir_values_13[discard_until+1:]) # to account for self
        tls_b_values_13 = np.array(tls_b_values_13[discard_until+1:])

    
    ## Discard handshake
    
    tls_dir_values_13 = tls_dir_values_13[tls_dir_values_13 != -1]
    tls_b_values_13 = tls_b_values_13[tls_b_values_13 != -1]
    #tls_tp_values_13 = tls_tp_values_13[tls_tp_values_13 != -1]
    
    if len(tls_b_values_13) == 0:
        # empty after removing handshake
        return [],[]
    
    # Remove trailing 19
    if remove_trailing_19:
        #if tls_b_values_13[-1] == 19:
        # Look for a Finished in each direction:
        # Starting with C2S
        replace_index = np.where((tls_b_values_13==19) & (tls_dir_values_13==0))[0]
        # If there is a C2S message with size 19
        if len(replace_index):
            # And if this is the last C2S message:
            if replace_index.max() == np.where(tls_dir_values_13==0)[0].max():
                tls_dir_values_13 = np.concatenate([tls_dir_values_13[:replace_index.max()],
                                                    tls_dir_values_13[replace_index.max()+1:]])
                tls_b_values_13 = np.concatenate([tls_b_values_13[:replace_index.max()],
                                                  tls_b_values_13[replace_index.max()+1:]])
            # Else we do nothing.

        # There could be a Finished message in each direction (rare but possible)
        # Check S2C...
        replace_index = np.where((tls_b_values_13==19) & (tls_dir_values_13==1))[0]
        if len(replace_index):
            if replace_index.max() == np.where(tls_dir_values_13==1)[0].max():
                tls_dir_values_13 = np.concatenate([tls_dir_values_13[:replace_index.max()],
                                                    tls_dir_values_13[replace_index.max()+1:]])
                tls_b_values_13 = np.concatenate([tls_b_values_13[:replace_index.max()],
                                                  tls_b_values_13[replace_index.max()+1:]])
    if len(tls_b_values_13) == 0:
        # empty after removing handshake
        return [],[]
    
    # Subtract 17? We won't generaly discard the 17 bytes of overhead,
    # because TLS 1.2 also added its own overhead (>20bytes, ~25).
    if subtract_17:
        tls_b_values_13 = tls_b_values_13 - 17

    #return tls_b_values_13, tls_dir_values_13
    
    #firstC2S = -1
    c2s_records = np.where((tls_dir_values_13==0))[0]
    if not len(c2s_records):
        # No C2S found (besides finished -- strange behavior)
        # Should we still remove the (presumable) NSTs ? -- hard to tell what is NST
        return tls_b_values_13, tls_dir_values_13
    firstC2S = c2s_records.min()
    
    #for i in range(len(tls_dir_values_13)): # look for first app data C2S
    #    if tls_dir_values_13[i] == 0:
    #        firstC2S = i
    #        break
    #if firstC2S == -1:
    #    #return [],[],[] # No C2S found (besides finished -- strange behavior)
    #    return tls_b_values_13, tls_dir_values_13
    #secondC2S = -1
    
    # if there are 2 consecutive c2s, we can't be sure if the s2c records are just
    # their replies. in that case, we won't look for NSTs, unless there are s2c
    # records even before the c2s ones.
    consecutive_c2s = False
    secondC2S = len(tls_dir_values_13) # if we don't find a second C2S, default is to consider all recs
    if len(tls_dir_values_13) >= firstC2S+2:
        # if (len(tls_dir_values_13) < firstC2S+2) => (len(tls_dir_values_13) == firstC2S+1),
        # meaning that there are no records beyond the first C2S record. 
        if tls_dir_values_13[firstC2S+1] == 0:
            consecutive_c2s = True
            # secondC2S = firstC2S+1
            # consecutive C2S, we won't consider it as the "second C2S"
        else:
            # since the firstC2S+1 is S2C, look for another C2S:
            for i in range(firstC2S+2, len(tls_dir_values_13)):
                if tls_dir_values_13[i] == 0:
                    secondC2S = i
                    break
    
    #if secondC2S == -1:
    #    # there is no second request -- one req, one response, so we consider all records
    #    secondC2S = len(tls_dir_values_13)
    
    #print(firstC2S, secondC2S, len(tls_dir_values_13))
    # look for NST in S2C records until the second client request:
    int_records_ind = [(a,c) for a, b, c in zip(list(tls_b_values_13[:secondC2S]), 
                                                list(tls_dir_values_13[:secondC2S]),
                                                list(range(secondC2S)) )
                             if (b == 1)]
    int_records = [a for a,b in int_records_ind]
    
    if len(int_records) <= 1:
        # One response to one request, cannot be sure, probably no NST
        # (or no response from the server at all)
        return tls_b_values_13, tls_dir_values_13
    
    if int_records_ind[0][1] < firstC2S:
        # a response even before a request -- most likely NST (but perhaps not).
        if (int_records[0] <= 600) and (int_records[0] >= 100):
            # size matches a plausible NST.
            nst_size = int_records[0]
            # exclude int_records of size nst_size (only look at the first 4 S2C)
            indices_to_remove = [b for a,b in int_records_ind[:4] if a == nst_size]
            return [tls_b_values_13[i] for i in range(len(tls_b_values_13)) if i not in indices_to_remove], \
                   [tls_dir_values_13[i] for i in range(len(tls_dir_values_13)) if i not in indices_to_remove]
        elif not consecutive_c2s:
            # if the size of the response doesn't match an NST, just ignore.
            # Instead: Look for NST in the next records (after first S2C)
            first_s2c_to_consider = [a[1] for a in int_records_ind if a[1] > firstC2S]
            if not len(first_s2c_to_consider):
                return tls_b_values_13, tls_dir_values_13
            first_s2c_to_consider = first_s2c_to_consider[0]
            if first_s2c_to_consider >= len(int_records_ind):
                return tls_b_values_13, tls_dir_values_13
            if (int_records_ind[first_s2c_to_consider][0] <= 600) and (int_records_ind[first_s2c_to_consider][0] >= 100):
                nst_size = int_records_ind[first_s2c_to_consider][0]
                indices_to_remove = [b for a,b in int_records_ind if a == nst_size]
                if len(indices_to_remove) < 3:
                    return [tls_b_values_13[i] for i in range(len(tls_b_values_13)) if i not in indices_to_remove], \
                       [tls_dir_values_13[i] for i in range(len(tls_dir_values_13)) if i not in indices_to_remove]
        return tls_b_values_13, tls_dir_values_13
    
    elif len(int_records) == 2: # Notice the else -- right here the S2C didn't come before C2S
        # discard first
        # in the unlikely even that the two are equal, we exclude both
        # unless they are the only server response -- sending only NST and closing would be atypical
        if consecutive_c2s:
            # Not sure, could be two replies
            return list(tls_b_values_13[:int_records_ind[0][1]]) + list(tls_b_values_13[int_records_ind[0][1]+1:]), \
                       list(tls_dir_values_13[:int_records_ind[0][1]]) + list(tls_dir_values_13[int_records_ind[0][1]+1:])
        elif (int_records[0] == int_records[1]) and (secondC2S != len(tls_dir_values_13)):
            # Both excluded -- making sure it is not the only request/response
            return list(tls_b_values_13[:int_records_ind[0][1]]) + list(tls_b_values_13[int_records_ind[1][1]+1:]), \
                   list(tls_dir_values_13[:int_records_ind[0][1]]) + list(tls_dir_values_13[int_records_ind[1][1]+1:])
        else:
            # Only the first one matching the size is excluded:
            if (int_records[0] <= 600) and (int_records[0] >= 100):
                return list(tls_b_values_13[:int_records_ind[0][1]]) + list(tls_b_values_13[int_records_ind[0][1]+1:]), \
                       list(tls_dir_values_13[:int_records_ind[0][1]]) + list(tls_dir_values_13[int_records_ind[0][1]+1:])
            elif (int_records[1] <= 600) and (int_records[1] >= 100):
                return list(tls_b_values_13[:int_records_ind[1][1]]) + list(tls_b_values_13[int_records_ind[1][1]+1:]), \
                       list(tls_dir_values_13[:int_records_ind[1][1]]) + list(tls_dir_values_13[int_records_ind[1][1]+1:])
            else:
                return tls_b_values_13, tls_dir_values_13
    else:
        # more than two responses to the first request
        # mark the first as NST, and the next ones of the same size 
        # unless the first one is too large or too small (not common for NST)
        if (int_records[0] <= 600) and (int_records[0] >= 100):
            nst_size = int_records[0]
        elif (int_records[1] <= 600) and (int_records[1] >= 100):
            nst_size = int_records[1]
        else:
            return tls_b_values_13, tls_dir_values_13
        
        # else: choose the one with the most repetitions -- this would only work
        # if we ignore the client requests, and look only at server responses, but
        # can we be sure that a repeated, same size response is necessarily an NST?
        #values, counts = np.unique(int_records, return_counts=True)
        #ind = np.argmax(counts)
        #if (np.max(counts) > 1) and (values[ind] < 1000) and (values[ind] > 60):
        #    nst_size = values[ind]
        
        # exclude int_records of size nst_size
        indices_to_remove = [b for a,b in int_records_ind if a == nst_size]
        
        # instead of excluding only int_records, should we exclude all consecutive records? probably not
        nst_discard_b, nst_discard_dir = \
               [tls_b_values_13[i] for i in range(len(tls_b_values_13)) if i not in indices_to_remove], \
               [tls_dir_values_13[i] for i in range(len(tls_dir_values_13)) if i not in indices_to_remove]
        
        return nst_discard_b, nst_discard_dir

def justify(a, invalid_val=0, axis=1, side='left'):    
    """
    https://stackoverflow.com/a/44559180
    Justifies a 2D array

    Parameters
    ----------
    A : ndarray
        Input array to be justified
    axis : int
        Axis along which justification is to be made
    side : str
        Direction of justification. It could be 'left', 'right', 'up', 'down'
        It should be 'left' or 'right' for axis=1 and 'up' or 'down' for axis=0.

    """

    if invalid_val is np.nan:
        mask = ~np.isnan(a)
    else:
        mask = a!=invalid_val
    justified_mask = np.sort(mask,axis=axis)
    if (side=='up') | (side=='left'):
        justified_mask = np.flip(justified_mask,axis=axis)
    out = np.full(a.shape, invalid_val) 
    if axis==1:
        out[justified_mask] = a[mask]
    else:
        out.T[justified_mask.T] = a.T[mask.T]
    return out 

def tls_12_appdata_filtering(dataframe):
    """
    Filters a dataframe of flows (each one having 20 tls_dir, tls_b and tls_tp columns),
    keeping only the records that have type 23 (0x17, or Application Data).
    The dataframe is justified, and padded with '-1' values.
    """
    tls_dir = ['tls_dir_'+str(x) for x in range(20)]
    tls_bs = ['tls_b_'+str(x) for x in range(20)]
    tls_tps = ['tls_tp_'+str(x) for x in range(20)]
    
    bs_values = justify( dataframe[tls_bs][dataframe[tls_tps].eq(23).rename(columns=dict(zip(tls_tps, tls_bs)))].values,
                         invalid_val=np.nan, axis=1, side='left' )
    
    dir_values = justify( dataframe[tls_dir][dataframe[tls_tps].eq(23).rename(columns=dict(zip(tls_tps, tls_dir)))].values,
                          invalid_val=np.nan, axis=1, side='left' )
    
    return pd.concat([pd.DataFrame(bs_values, columns=tls_bs ).replace(np.nan, -1), 
                      pd.DataFrame(dir_values, columns=tls_dir ).replace(np.nan, -1)], axis=1).set_index(dataframe.index)

def remove_empty(dataframe, print_removed=False):
    """
    Removes empty rows from the dataframe (those for which all tls_b values == -1).
    -------------
    print_removed : boolean
        Whether to print the number of empty (removed) rows.
    """
    tls_bs = ['tls_b_'+str(x) for x in range(20)]
    to_remove = dataframe[ (dataframe[tls_bs] == -1).all(axis=1) ].index
    if print_removed:
        print(len(to_remove))
    dataframe.drop(to_remove, inplace=True)