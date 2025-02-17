#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Dec 21 11:27:51 2024

@author: aymen
"""

class CERT:
    __titre = "Titre de l'alerte"
    __description = ""
    __lien = "Entry"
    __date="Date"
    __type="Avis ou Alerte"
    CVE=[]
    
    

        
        
    def __init__ (self, titre, lien,description,date):
        self.__titre=titre
        self.__lien = lien 
        self.__description = description
        self.__date=date
        self.CVE = []
        
        
     # Getter et Setter pour __titre
    def get_titre(self):
        return self.__titre

    def set_titre(self, titre):
        self.__titre = titre

    # Getter et Setter pour __description
    def get_description(self):
        return self.__description

    def set_description(self, description):
        self.__description = description

    # Getter et Setter pour __lien
    def get_lien(self):
        return self.__lien

    def set_lien(self, lien):
        self.__lien = lien

    # Getter et Setter pour __date
    def get_date(self):
        return self.__date

    def set_date(self, date):
        self.__date = date
        
    def get_CVE(self):
        return self.__CVE
    
    def get_CVE_index(self,i):
        return self.__CVE[i]
    
    def set_CVE(self,CVE):
        self.__CVE.append(CVE)
        
        
    def get_type(self):
        return self.__type

    def set_type(self, bulletin):
        self.__type= bulletin
        
        
class CVE:
    __nom = "name"
    __lien= "lien"
    
    def __init__(self, nom, lien):
        self.__nom= nom
        self.__lien= lien
    
    def get_nom(self):
        return self.__nom
    
    def set_nom(self, nom):
        self.__nom = nom
        
    def get_lien(self):
        return self.__lien
    
    def set_lien(self,lien):
        self.__lien=lien
    
    
