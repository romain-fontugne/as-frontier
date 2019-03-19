% TrafficSSL1.m 
% PA, RF, EB, Tokyo, Japan, March 2019
% Tries SSL on AS graphs

clc
clear all
close all 
format compact
addpath(genpath('/Users/pabry/MATLAB/SSL/My-toolboxes/')) % EB Toolbox path 
addpath(genpath('/Users/pabry/MATLAB/TRAFFIC0/TrafficSSL/as-frontier/')) % RF Graph Data 

%% AS Graph Data by Romain
load ground_truth.txt ; GT = ground_truth' ; 
load ip_graph.txt ; A = ip_graph ; 
load expert_strict.txt ; expert_strict = expert_strict' ;% Strategy AS
load expert_loose.txt ; expert_loose = expert_loose' ; % Strategy AS : all nodes are tagged but do not trust 
load expert_weighted.txt ; expert_weighted = expert_weighted' ; % Strategy AS : all nodes are tagged but weighted and may have weights in different classes
% node_labels = fileread('node_labels.txt') ; expert_weighted
fid = fopen('node_labels.txt') ;
C = textscan(fid,'%s') ; 
node_labels = C{1} ; 

% 
CEG = zeros(length(expert_strict),1) ; 
for k=1:1:length(expert_strict)
   tmp  = find(expert_strict(k,:) == 1) ; 
   if ~isempty(tmp)
       CEG(k) = tmp ;
   end
end

CEB = zeros(length(expert_strict),1) ; 
for k=1:1:length(expert_strict)
   tmp  = find(expert_loose(k,:) == 1) ; 
   if ~isempty(tmp)
       CEB(k) = tmp ;
   end
end

CGT = zeros(length(GT),1) ; 
for k=1:1:length(GT)
   tmp  = find(GT(k,:) == 1) ; 
   if ~isempty(tmp)
       CGT(k) = tmp ;
   end
end

CEW = zeros(length(expert_strict),1) ; 
for k=1:1:length(expert_strict)
   tmp  = find(expert_weighted(k,:) == max(1e-5,max(expert_weighted(k,:)))) ; 
   if ~isempty(tmp)
       CEW(k) = tmp ;
   end
end


%% 
sigma = 0 ; % PR 
gamma = 2 ; 
% [partition] = gamma_PageRank(A,Y,'sweep-cut','exact','manual','MU',mu,'GAMMA',gamma); % best mu for gamma_star
mu = 0.5 ;  [PEG1,gamma,mu,FEG1] = gamma_PageRank(A,expert_strict,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 
mu = 1.0 ;  [PEG2,gamma,mu,FEG2] = gamma_PageRank(A,expert_strict,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 
mu = 1.5 ;  [PEG3,gamma,mu,FEG3] = gamma_PageRank(A,expert_strict,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 

mu = 0.10 ;  [PEB1,gamma,mu,FEB1] = gamma_PageRank(A,expert_loose,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 
mu = 0.25 ;  [PEW1,gamma,mu,FEW1] = gamma_PageRank(A,expert_weighted,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 


%% results
if 1 % Compare good (high mu) and bad (low mu) experts 
    PEG = PEG1 ; FEG = FEG1 ; 
    PEB = PEB1 ; FEB = FEB1 ; 
    PEW = PEW1 ; FEW = FEW1 ; 
clc
%[node_labels partition Y]
display('Partitions')
for k=1:1:length(expert_strict)
    display([num2str(k),cellstr(node_labels(k)),num2str(PEG(k)),num2str(PEB(k)),num2str(PEW(k))])
%    blah=[num2str(k),cellstr(node_labels(k)),num2str(partition2(k)),num2str(partition4(k))] 
%    fprintf('%s\n',cellstr(blah)) 
end
display('Partitions when good and bad expert partitions disagree')
for k=1:1:length(expert_strict)
    if PEG(k) ~= PEB(k)
        display([num2str(k),cellstr(node_labels(k)),num2str(PEG(k)),num2str(PEB(k))])
    end
end
display('Partitions per class from Good experts')
[a,b] = size(GT) ; 
for n = 1:b
    n
    index = find(PEG==n) ; 
    for k = 1:1:length(index)
        display([num2str(index(k)),cellstr(node_labels(index(k))),num2str(PEG(index(k))),num2str(PEB(index(k)))])
    end
end
display('Partitions per class from Bad experts')
for n = 1:b
    n
    index = find(PEB==n) ; 
    for k = 1:1:length(index)
        display([num2str(index(k)),cellstr(node_labels(index(k))),num2str(PEG(index(k))),num2str(PEB(index(k)))])
    end
end

display('Partitions per class from Ground truth')
for n = 1:b
    n
    index = find(CGT==n) ; 
    for k = 1:1:length(index)
        display([num2str(index(k)),CGT(index(k)),cellstr(node_labels(index(k))),num2str(PEG(index(k))),num2str(CEG(index(k))),num2str(PEB(index(k))),num2str(CEB(index(k)))])
    end
end

display('Focus on when GoodExpert partitions disagree with Ground truth')
for k=1:1:length(expert_strict)
    if CEG(k) ~= CGT(k)
        display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEG((k))),num2str(CEG((k))),num2str(PEB((k))),num2str(CEB((k)))])
    end
end
display('Focus on when BadExpert partitions disagree with Ground truth')
for k=1:1:length(expert_strict)
    if CEB(k) ~= CGT(k)
        display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEG((k))),num2str(CEG((k))),num2str(PEB((k))),num2str(CEB((k)))])
    end
end

display('Focus on BadExpert when partitions disagree with a priori info')
display('Relevant disagreement')
for k=1:1:length(expert_strict)
    if CEB(k) ~= PEB(k)
        if PEB(k) == CGT(k)
            display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEG((k))),num2str(CEG((k))),num2str(PEB((k))),num2str(CEB((k)))])
        end
    end
end
display('Irrelevant disagreement')
for k=1:1:length(expert_strict)
    if CEB(k) ~= PEB(k)
        if CEB(k) == CGT(k)
            display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEG((k))),num2str(CEG((k))),num2str(PEB((k))),num2str(CEB((k)))])
        end
    end
end

display('Focus on LooseExperts when partitions disagree with expert a priori')
display('Relevant disagreement')
for k=1:1:length(expert_strict)
    if PEW(k) == PEB(k)
        if PEW(k) == CGT(k)
            display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEW((k))),num2str(CEW((k))),num2str(PEB((k))),num2str(CEB((k)))])
        end
    end
end
display('Irrelevant disagreement')
for k=1:1:length(expert_strict)
    if CEW(k) ~= PEW(k)
        if CEW(k) == CGT(k)
            display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEW((k))),num2str(CEW((k))),num2str(PEB((k))),num2str(CEB((k)))])
        end
    end
end

display('Focus on LooseExperts')
index = find(CGT~=CEW) ; length(index) 
display('Relevant: C not= GD But P = GT ')
for k=1:1:length(expert_strict)
    if and(PEW(k) == CGT(k),(CEW(k)~=CGT(k)))
        display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEW((k))),num2str(CEW((k)))])
    end
end
display('Irrelevant: C == GD and P not= GT')
for k=1:1:length(expert_strict)
    if and(PEW(k) ~= CGT(k),(CEW(k)==CGT(k)))
        display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEW((k))),num2str(CEW((k)))])
    end
end

if 0
display('Case study')
k = 8 ; 
display([num2str(k),CGT((k)),cellstr(node_labels(k)),num2str(PEG((k))),num2str(CEG((k))),num2str(PEB((k))),num2str(CEB((k)))])
FEG(k,:)
FEB(k,:)
end

end

if 0 % Compare good experts with different mu
clc
%[node_labels partition Y]
for k=1:1:length(Y)
    [k node_labels(k) PEG1(k) PEG2(k) PEG3(k) Y(k,:)]
end
end

%% Check for optimal gamma 
if 0
mu = 0.5 ;  [PEG1,gamma,mu,FEG1] = gamma_PageRank(A,expert_strict,'multi-class','exact','manual','MU',mu,'GAMMA',gamma); 
mu = 0.5 ;  [PEGG1, gamma_found,mu,FEGG1] = gamma_PageRank(A,expert_strict,'multi-class','exact','semi-automatic','MU',mu); % keep same mu as gamma optimal
gamma_found
end

