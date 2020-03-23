# /////////////////////////////////////////////////////////////// #
# Helper Functions ////////////////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #


# Reads in the dictionary data
import pandas as pd
csd = pd.read_csv('csd.csv')

# Creates a dictionary for looking up dictionary categories (lexemes as keys and categories as values)
csdlookup = {}
for i,r in csd.iterrows():
    for lex in r['lexemes'].split(';'):
        csdlookup[lex.strip()] = r['catkey']

# Creates a dictionary for looking up category labels
# the full category key is formatted as follows: 
# dictionary(s,c)_categroy(smech,tgen,etc)_concept(malware,phish)_term(virus)_domain(cs,s,c,g)
# e.g., s_tttp_malw_virus_dcs
csdlabs = {}
for i,r in csd.iterrows():
    # takes the category portion (e.g., 's_tttp') from the full dictionary key 
    # and assigns a category label 'Threat Mechanism'
    cat = '_'.join(r['catkey'].split('_')[:2])
    csdlabs[cat] = r['cat']
    # takes the concept portion (e.g., 's_tttp_malw') of the full dictionary key 
    # and assigns a category label 'Malware'
    concept = '_'.join(r['catkey'].split('_')[:3])
    csdlabs[concept] = r['concept']
    # takes the concept portion (e.g., '_dcs') of the full dictionary key 
    # and assigns a category label 'Cyber Security'
    dom = r['catkey'].split('_')[4]
    csdlabs[dom] = r['domain']

# Lists of domain tokens
dcs_list = [k for k,v in csdlookup.items() if '_dcs' in v]
dc_list = [k for k,v in csdlookup.items() if '_dc' in v]
ds_list = [k for k,v in csdlookup.items() if '_ds' in v]

# Gets category key and desired level; returns label
def parsecat(cat,level,show=True):
    if level=='category':
        res = '_'.join(cat.split('_')[:2])
    if level=='concept':
        res = '_'.join(cat.split('_')[:3])
    if level=='term':
        res = '_'.join(cat.split('_')[:4])
    if level=='domain':
        res = cat.split('_')[4]
    if show == True:
        res = csdlabs[res]
    return res

# /////////////////////////////////////////////////////////////// #
# Visualise Framework /////////////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #

# Takes dictionary. Has options to output a sunburst graph or a table, with concepts, and list of terms
def tacs_show(out = 'vis', dictionary = csd, level = 'concept', context=True):
    
    if out == 'table':
        if level=='concept':
            dictionary['term_domain'] = dictionary['term'] + ['('+''.join([i[0] for i in x.split(' ')])+')' for x in dictionary.domain]
            res = dictionary[['dict','cat','concept','term_domain']].sort_values(['dict','cat','concept'],ascending=False)
        if level=='cat':
            dictionary['concept_domain'] = dictionary['concept'] + ['('+''.join([i[0] for i in x.split(' ')])+')' for x in dictionary.domain]
            res = dictionary[['dict','cat','concept_domain']].sort_values(['dict','cat'],ascending=False)
        res = res.drop_duplicates().groupby([x for x in res.columns[:-1]])[res.columns[-1]].apply(lambda x: ', '.join(x))
        res = pd.DataFrame(res).sort_index(ascending=False)        
        return res
    
    # Option to include Terms
    if out == 'vis':
        pdatlist=[]
        dictionary = dictionary[['dict','cat','concept']].drop_duplicates()
        dictionary = dictionary.replace({"cat": {'Security General':'S General',
                            'Security Mechanism':'S Mechanism',
                           'Threat General':'T General',
                           'Threat Mechanism':'T Mechanism',
                           'Threat Actor':'T Actor',
                           'Security Actor':'S Actor'}})
        dat = dictionary[(dictionary['cat']!='Cybersecurity') & (dictionary['dict']=='Security')]
        pdat = [
         ('Safety','Security'),
         ('S General','Safety'),
         ('S Mechanism','Safety'),
         ('S Actor','Safety'),
         ('T Actor','Threat'),
         ('Security',''),
         ('Threat','Security'),
         ('T General','Threat'),
         ('T Mechanism','Threat')]

        pdat.extend([(r.concept+' ',r['cat']) for i,r in dat.iterrows()])
        pdat = pd.DataFrame(pdat, columns = ['labels','parents'])
        if context==True:
            pdatlist.append(pdat)
            dat = dictionary[(dictionary['cat']!='Cybersecurity') & (dictionary['dict']=='Context')]
            pdat = [
             ('Context',''),
             ('Quality','Context'),
             ('Org','Context'),
             ('Individual','Context'),
             ('Cyber Entity','Context'),
             ('Activity','Context')]

            pdat.extend([(r.concept+' ',r['cat']) for i,r in dat.iterrows()])
            pdatlist.append(pd.DataFrame(pdat, columns = ['labels','parents']))

        import plotly.express as px
        import plotly.graph_objects as go

        layout = go.Layout(
        grid=go.layout.Grid(columns=2, rows=1),
        margin = go.layout.Margin(t=0, l=0, r=0, b=0),
        sunburstcolorway=[
        "#F23843","#2C54B8","#2F4F4F","#2F4F4F","#2F4F4F",
            "#2F4F4F","#2F4F4F","#2F4F4F","#2F4F4F","#2F4F4F",
            "#2F4F4F","#D7D7D7","#D7D7D7","#D7D7D7","#D7D7D7",
            "#D7D7D7","#D7D7D7","#D7D7D7","#D7D7D7","#D7D7D7"],
        extendsunburstcolors=True)


        if len(pdatlist) < 2:

            df = pdat
            trace1 = go.Sunburst(
                labels=df.labels,
                parents=df.parents,
                maxdepth=3,
                insidetextfont = {"size": 11}
            )

            fig = go.Figure([trace1], layout)        
            return fig.show()

        if len(pdatlist) == 2:
            df1 = pdatlist[0]
            df2 = pdatlist[1]
                        
            trace1 = go.Sunburst(
                labels=df1.labels,
                parents=df1.parents,
                maxdepth=4,
                domain=dict(column=0),
                insidetextfont = {"size": 11}
            )
            
            trace2 = go.Sunburst(
                labels=df2.labels,
                parents=df2.parents,
                maxdepth=3,
                domain=dict(column=1),
                insidetextfont = {"size": 11}
            )

            fig = go.Figure([trace1,trace2], layout)   
            return fig.show()
    
    

# /////////////////////////////////////////////////////////////// #
# Tokenisation & Tagging //////////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #


def tacs_tag(docs,context_rule=True,context_window=8):

    # TODO if input is df, return same df with 'tacs' column  
    
    out=None
    if type(docs)==str:
        out = 'string'
        docs = [docs]

    import spacy
    import spacy
    from spacy.tokens import Token
    # Create a custom token attribute 'csd'
    Token.set_extension("csd", default='None',force=True)  
    nlp = spacy.load("en_core_web_sm")

    tokdocs = []
    for doc in docs:
        # Find ngrams before tokenisation and join them with '_'
        ngrams = []
        ngrams.append([x for x in csdlookup.keys() if len(x.split('_'))==3])
        ngrams.append([x for x in csdlookup.keys() if len(x.split('_'))==2])
        import re
        for ngs in ngrams:
            for ng in ngs:
                foo=re.compile(re.escape(' '.join(ng.split('_'))), re.IGNORECASE)
                doc = foo.sub('_'.join(ng.split(' ')),doc)      

        # Tokenise with spacy
        doc = nlp(doc)

        # For each token...
        for tok in doc:
            # Try if token is in dictionary
            try:
                # If the token is non in the dictionary, this will throw an error missing key and terminate the iteration
                csdlookup[tok.lower_]

                # If context rule is disabled, directly tag all tokens. Not recommended for longer texts with mixed topics.
                if context_rule==False:
                    tok._.csd = csdlookup[tok.lower_]

                # If context rule is enabled (default), tag non-CS tokens only if near CS tokens or both S and C tokens   
                if context_rule!=False:
                    # Directly tag Cyber-Security words (e.g., password, hackers, computer_security)
                    if tok.lower_ in dcs_list:
                        tok._.csd=csdlookup[tok.lower_]
                    # For words from other domains, get neighbouring tokens 
                    else:
                        # Adds n=context_window left-hand side tokens and n=context_window right-hand side tokens
                        neighbours=[]
                        window_start = tok.i-context_window if tok.i-context_window>=0 else 0
                        window_end = context_window+tok.i if context_window+tok.i<=len(doc) else len(doc)
                        neighbours.extend(doc[window_start:window_end])
                        
                        has_cs= any(x.lower_ in dcs_list for x in neighbours)
                        has_s = any(x.lower_ in dc_list for x in neighbours)
                        has_c = any(x.lower_ in ds_list for x in neighbours)
                        if (context_rule==True)|(context_rule=='cs|(c&s)'):
                            if (has_cs)|((has_s)&(has_c)):
                                tok._.csd=csdlookup[tok.lower_]
                        if (context_rule=='cs'):
                            if (has_cs):
                                tok._.csd=csdlookup[tok.lower_]
            except:
                ''
        tokdocs.append(doc)
        
        if out == 'string':
            tokdocs = tokdocs[0]

    return tokdocs


# /////////////////////////////////////////////////////////////// #
# Counting & Frequency Tables /////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #


def tacs_count(data, level='concept', aggr='all', subcount = True, textcol='text'):
    
    # Find/Produce tacs-tagged documents from input; same across functions; needs improving
    if isinstance(data, pd.DataFrame)==False:
        docs = data
    else:
        try:
            print('Tagging documents. This might take a couple of minutes.')
            tacs_col = [x for x in data.columns if 'spacy' in str(type(data[x][0]))][0]
            docs = data[tacs_col].tolist()
        except:
            docs = tacs_tag(data[textcol])
    
    from collections import Counter
    # Creates a table with full category and concept labels
    freqtab = pd.DataFrame()
    freqtab[['dict','cat','concept','term']] = csd[['dict','cat','concept','term']]
    freqtab = freqtab.set_index(csd['catkey'])

    if aggr not in ['all','each']:
        if isinstance(aggr,list):
            grp = aggr
        elif isinstance(data, pd.DataFrame) & (aggr in data.columns):
            grp = data[aggr]
        
        # Aggregates documents by grouping variable.
        # The grp list should correspond to the document list. 
        # Iterates through each unique value in the grp list.
        for g in set(grp):
            # Iterates through each element of the document lists and returns the documents
            # whose id matches the current group (g) according to the grp list
            doc_ = [docs[i] for i in range(len(docs)) if grp[i] == g]
            doc_ = [tok for doc in doc_ for tok in doc]
            # Counts dictionary keys (using the full key means that each unique Term is counted) and adds frequency to frequency table
            freqdict = Counter([tok._.csd for tok in doc_ if tok._.csd!=None])
            freqtab['doc_'+str(g)] = [freqdict[i] if i in freqdict.keys() else 0 for i in freqtab.index]
        # Aggregates frequencies by specified level
        if level=='cat':
            res = freqtab.reset_index().groupby(['dict','cat']).sum()
        if level=='concept':
            res = freqtab.reset_index().groupby(['dict','cat','concept']).sum()

    elif aggr=='all': 

        doc = [tok for doc in docs for tok in doc]

        # Counts dictionary keys (using the full key means that each unique Term is counted) and adds frequency to frequency table
        freqdict = Counter([tok._.csd for tok in doc if tok._.csd!=None])
        freqtab['freq'] = [freqdict[i] if i in freqdict.keys() else 0 for i in freqtab.index]  

        # Aggregates frequencies by specified level and ..,
        # displays top 3 instances of the lower level and their frequencies as a string
        # Sets corresponding column names for the subsequent aggregation operations.
        if level=='concept':
            x='term'
            cols = ['dict','cat','concept']
        if level=='cat':
            x='concept'
            cols = ['dict','cat']
            print(cols)
            freqtab = freqtab.groupby(['dict','cat','concept'])['freq'].sum().reset_index().sort_values(['dict','cat','freq'],ascending=False)

        # Appends the frequency of a Term to its label, with _
        freqtab[x] = [r[x]+'_'+str(r['freq']) for i,r in freqtab.iterrows()]
        # Creates a table topt with a list of top 3 terms per concept
        topt = freqtab[freqtab.freq>0].sort_values([level,'freq'],ascending=False).groupby([level]).head(3)
        topt = topt.groupby([x for x in topt.columns[:-2]])[x].apply(lambda x: ','.join(x))
        # Aggregates frequencies by concepts (sums term frequencies)
        freqtab = freqtab[freqtab.freq>0].groupby(cols)['freq'].sum().reset_index().sort_values(cols+['freq'],ascending=False).set_index(cols)
        # Adds top 3 terms from topt to aggregated frequency table
        for i in freqtab.index:
            try:
                freqtab.loc[i,'top_sub'] = topt[i]
            except:
                freqtab.loc[i,'top_sub'] = ''
        freqtab.columns=['freq','top_sub']
        res = freqtab
        
    elif aggr=='each':
        # For each document...
        for i in range(len(docs)):
            # Counts dictionary keys (using the full key means that each unique Term is counted) and adds frequency to frequency table
            freqdict = Counter([tok._.csd for tok in docs[i] if tok._.csd!=None])
            freqtab['doc_'+str(i)] = [freqdict[i] if i in freqdict.keys() else 0 for i in freqtab.index]
        
        # Aggregates frequencies by specified level
        if level=='category':
            res = freqtab.reset_index().groupby(['dict','cat']).sum()
        if level=='concept':
            res = freqtab.reset_index().groupby(['dict','cat','concept']).sum()

    res.to_csv('tacs_freq.csv')
    return res


# /////////////////////////////////////////////////////////////// #
# Text Annotation /////////////////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #

# Annotation. Takes a tacs-tagged spacy document (or sentence). Returns annotated html or plain text.
def tacs_annotate_doc(doc, render = False, custom=False, level='concept', context=True):
    out = '<style>.tacstok{font-weight:bold}</style>'
    for tok in doc:
        #print(tok._.csd, context)
        if tok._.csd=='None':
            if tok.is_punct:
                out = out +tok.text
            else:
                out = out +' '+ tok.text
        elif custom != False:
            tokcats = [tok._.csd,parsecat(str(tok._.csd),level='concept'),parsecat(str(tok._.csd),level='category')]
            if any([custom in x for x in tokcats]):
                out=out+' '.join(['<span class="tacstok">&nbsp',
                           tok.text,
                           '</span><sub> ',
                           parsecat(str(tok._.csd),level=level),
                           ' </sub>&nbsp'])

        elif context == False:
            if (tok._.csd.startswith('c_')):
                out=out+tok.text+' '
            else:
                out=out+' '.join(['<span class="tacstok">&nbsp',
                           tok.text,
                           '</span><sub> ',
                           parsecat(str(tok._.csd),level=level),
                           ' </sub>&nbsp'])
        elif context == True:
            out=out+' '.join(['<span class="tacstok">&nbsp',
                           tok.text,
                           '</span><sub> ',
                           parsecat(str(tok._.csd),level=level),
                           ' </sub>&nbsp'])
    if render==True:        
        from IPython.core.display import display, HTML
        display(HTML(out))
    else:
        return out
    
# Prints in notebook. Saves as output.
def tacs_annotate(data, annot='html', show_annot = True, custom=False, level='concept', context=True, textcol='text'):
    
    # Find/Produce tacs-tagged documents from input; same across functions; needs improving
    if isinstance(data, pd.DataFrame)==False:
        docs = data
    else:
        try:
            tacs_col = [x for x in data.columns if 'spacy' in str(type(data[x][0]))][0]
            docs = data[tacs_col].tolist()
        except:
            print('Tagging documents. This might take a couple of minutes.')
            docs = tacs_tag(data[textcol])

    out = ''
    for doc in docs:
        out = out+'<h2>Document '+str(docs.index(doc))+'</h2>'
        out = out + tacs_annotate_doc(doc,custom=custom,level=level,context=context)    
    
    if annot == 'html':            
        Html_file= open('tacs_out.html',"w")
        Html_file.write(out)
        Html_file.close()
        
    if show_annot ==  True:
        from IPython.core.display import display, HTML
        display(HTML(out))

# /////////////////////////////////////////////////////////////// #
# Text Query //////////////////////////////////////////////////// #
# /////////////////////////////////////////////////////////////// #

def tacs_query(data, query, textcol='text',
               qsents = True, return_all = False, 
               data_return = False, data_save = True, 
               annot_return = True, annot_save = True,
               annot_markup = False, annot_level='concept'):
    
    level = annot_level
    # Find/Produce tacs-tagged documents from input; same across functions; needs improving
    if isinstance(data, pd.DataFrame)==False:
        docs = data
    else:
        try:
            tacs_col = [x for x in data.columns if 'spacy' in str(type(data[x][0]))][0]
            docs = data[tacs_col].tolist()
        except:
            print('Tagging documents. This might take a couple of minutes.')
            docs = tacs_tag(data[textcol])

    # Functions to parse query string
    # Separates OR clauses
    def get_sub_queries(query):
        for subquery in query.split(' OR '):
            yield subquery
    # Separates AND clauses
    def get_phrases(subquery):
        for phrase in subquery.split(' AND '):
            yield phrase
    # 1. Separates query by OR; 2. Separates each subclause by AND 
    def find(query, string):
        for subquery in get_sub_queries(query):
            if all(phrase in catstr for phrase in get_phrases(subquery)):
                return True
        return False
    
    # Matches will be an object with the same shape as docs, boolean values, True = unit matches query
    # sent nested in doc nested in docs if sents=True
    # doc nested in docs if sents=False
    matches = []
    for doc in docs:
        # For each document, checking if document or sentences matches condition.
        docmatches = []
        if qsents == True:
            for sent in doc.sents:
                # Creates a string of all TACS categories in the sentence
                # the list includes labels
                catstr = ' '.join([' '.join([tok._.csd,parsecat(tok._.csd,'category'),parsecat(tok._.csd,'concept'),parsecat(tok._.csd,'domain')]) for tok in sent if tok._.csd!='None'])
                #
                if find(query,catstr):
                    docmatches.append(True)
                else:
                    docmatches.append(False)
            matches.append(docmatches)
            
        else:
            # same as code used for sentences
            catstr = ' '.join([' '.join([tok._.csd,parsecat(tok._.csd,'category'),parsecat(tok._.csd,'concept'),parsecat(tok._.csd,'domain')]) for tok in doc if tok._.csd!='None'])
            if find(query,scats):
                matches.append(True)
            else:
                matches.append(False)
                
    # Function to return matching text as data or annotated html
    # For each doc/sentence, check matches doc 
    res = []
    for docid in range(len(docs)):
        doc = []
        if qsents == True:
            sents = [x for x in docs[docid].sents]
            for sentid in range(len(sents)):
                res.append([docid,sentid,sents[sentid].text,sents[sentid],matches[docid][sentid]])
                cols = ['docid','sentid','text','text_spacy','query']
        else:
            res.append([docid,docs[docid].text,docs[docid],matches[docid]])
            cols = ['docid','text','text_spacy','query']

    outdat = pd.DataFrame(res,columns = cols)
    
    if return_all==False:
        outdat = outdat[outdat['query']==True]
    
    if data_save == True:
        outdat.drop('text_spacy',axis=1).to_csv('tacsq_'+query+'.csv')
    
    if data_return == True:
        return outdat

    if annot_markup=='html':
    # Annotate: Two options
    # a. full text is returned, sentences matching the query are highlighted
    # b. only sentences matching the query are returned, with no highlighting
        outhtml = ''
        for docid in set(outdat.docid):
            outhtml = outhtml+'<h2>Document '+str(docid)+'</h2>'
            if return_all==False:
                outhtml = outhtml+'<ul>'
            for i,r in outdat[outdat.docid==docid].iterrows():
                if return_all == True:
                    if r['query'] == True:
                        outhtml = outhtml + '<span style="background-color:#cedde2">'+str(tacs_annotate_doc(r['text_spacy']))+'</span>'  
                    if r['query'] == False:
                        outhtml = outhtml + str(tacs_annotate_doc(r['text_spacy']))
                else:
                    if r['query'] == True:
                        outhtml = outhtml +'<li>'+str(tacs_annotate_doc(r['text_spacy']))+'</li>'  
            if return_all==False:
                outhtml = outhtml+'</ul>'

        if annot_save == True:
            Html_file= open('tacs_out.html',"w")
            Html_file.write(outhtml)
            Html_file.close()

        if annot_return == True:
            from IPython.core.display import display, HTML
            display(HTML(outhtml))
    
    #if annot=='rtf':


