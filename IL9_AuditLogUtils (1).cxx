/*************************************************************************************
* Copyright (c) 2019 Illumina
* All rights reserved
*
* File Name: IL9_AuditLogUtils.cxx
* Description:  This file contains common functions' definitions to fetch Audit Logs info
*
*
* History
* Date					Author					Description of Change
* 02/28/2022			Sudarshan Sawant		Initial Creation
**************************************************************************************/
#include "IL9_AuditLogUtils.hxx"
#include "IL9_ArgumentValidation.hxx"
#include "IL9_LogEntryExit.hxx"
#include "IL9_BusinessObjectUtils.hxx"
#include "IL9SimplePOMEnquiry.hxx"
#include "IL9_StringUtils.hxx"
#include "constants/IL9_TypeConstants.hxx"

#include <sa/audit.h>
#include <fclasses/tc_date.h>

#include <mld/logging/Logger.hxx>
#include <base_utils/TcResultStatus.hxx>
#include <base_utils/ScopedSmPtr.hxx>
#include <base_utils/IFail.hxx>

#include <tccore/grm.h>
#include <tccore/tctype.h>
#include <tccore/aom_prop.h>
#include "IL9_JournalLog.hxx"


using namespace Teamcenter;
using namespace il9::utils::POMEnquiry;
using namespace il9::utils::String;

int  il9_validateNonLongStringPropertyValues(tag_t ObjectTag, int row_index, int nCols, std::vector< il9::utils::AuditLog::ValidatePropertyInput > propNamesToValidate, void ***result, int &numOfModifiedProperties,
	std::unordered_set<std::string> &hsModifiedPropertyNames,
	std::vector< il9::utils::AuditLog::PropertyInfo > &modifiedProperties)
{
	int iFail = ITK_ok;
	ResultStatus status(0);

	////logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try
	{
		int indexPropInput = 0;

		for (int col_index = 1; propNamesToValidate.size() > indexPropInput && col_index < nCols - 2; col_index += 2)
		{
			if (propNamesToValidate[indexPropInput].iType == POM_long_string)
			{
				indexPropInput++;
				col_index -= 2;//reset column index to skip POM_long_string types properties while navigating through property input vector
				continue;
			}

			//fetch property values as per the order of select attributes of the query
			std::string szPropertyName(propNamesToValidate[indexPropInput].szPropertyName);
			std::string szPropertyNameOld(propNamesToValidate[indexPropInput].szPropertyNameOld);

			if (hsModifiedPropertyNames.find(szPropertyName) != hsModifiedPropertyNames.end())
			{
				//if change in property values is already detected for current property then skip current index
				indexPropInput++;
				continue;
			}

			//property values are fetched for each property pair of current and old property name		
			bool isModified = false;
			il9::utils::AuditLog::PropertyInfo tempPropInfo;

			//this function call compares old and new value for current property in each result row
			status = il9_checkIfPropertyModified(ObjectTag, propNamesToValidate[indexPropInput], result, col_index, row_index, isModified,
				tempPropInfo);

			if (isModified)
			{
				//populate output vector
				modifiedProperties.push_back(il9::utils::AuditLog::PropertyInfo());

				modifiedProperties[numOfModifiedProperties].szPropertyName = szPropertyName;
				modifiedProperties[numOfModifiedProperties].szCurrentValue = tempPropInfo.szCurrentValue;
				modifiedProperties[numOfModifiedProperties].szOldValue = tempPropInfo.szOldValue;

				numOfModifiedProperties++;

				hsModifiedPropertyNames.insert(szPropertyName);

				if (numOfModifiedProperties == propNamesToValidate.size()) break;
			}

			indexPropInput++;
		}
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}

int il9_validateLongStringPropertyValues(tag_t ObjectTag, tag_t auditObjectTag, std::vector< il9::utils::AuditLog::ValidatePropertyInput > propNamesToValidate,
	int &numOfModifiedProperties, std::unordered_set<std::string> &hsModifiedPropertyNames,
	std::vector< il9::utils::AuditLog::PropertyInfo > &modifiedProperties)
{
	int iFail = ITK_ok;
	ResultStatus status(0);

	////logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try 
	{
		for (int indexPropNames = 0; indexPropNames < propNamesToValidate.size(); indexPropNames++)
		{
			if (propNamesToValidate[indexPropNames].iType == POM_long_string)
			{
				bool isModified = false;
				il9::utils::AuditLog::PropertyInfo tempPropInfo;

				//this function call compares old and new value for current Long String Type property for each audit Object Result Tag
				status = il9_checkIfLongStringPropertyModified(ObjectTag, auditObjectTag, propNamesToValidate[indexPropNames].szPropertyName,
					propNamesToValidate[indexPropNames].szPropertyNameOld, isModified, tempPropInfo);

				if (isModified)
				{
					//populate output vector
					modifiedProperties.push_back(il9::utils::AuditLog::PropertyInfo());

					modifiedProperties[numOfModifiedProperties].szPropertyName = propNamesToValidate[indexPropNames].szPropertyName;
					modifiedProperties[numOfModifiedProperties].szCurrentValue = tempPropInfo.szCurrentValue;
					modifiedProperties[numOfModifiedProperties].szOldValue = tempPropInfo.szOldValue;

					numOfModifiedProperties++;

					hsModifiedPropertyNames.insert(propNamesToValidate[indexPropNames].szPropertyName);

					if (numOfModifiedProperties == propNamesToValidate.size()) break;
				}
			}
		}
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}

int il9_checkIfLongStringPropertyModified(tag_t ObjectTag, tag_t auditObjectTag, std::string szPropertyName, std::string szPropertyNameOld, bool &isModified,
	il9::utils::AuditLog::PropertyInfo & propertyInfo)
{
	int iFail = ITK_ok;
	ResultStatus status(0);
	isModified = false;

	////logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try
	{
		scoped_smptr<char*> value;
		int num_of_values = 0;
		status = AOM_ask_value_strings(ObjectTag, szPropertyName.c_str(), &num_of_values, &value);

		vector<string> vecCurrentValues;
		std::string strCurrentValue;

		if (num_of_values > 0)
		{
			strCurrentValue.append(value.get()[0]);
			vecCurrentValues.push_back(value.get()[0]);
	
			for (int currValueIndex = 1; currValueIndex < num_of_values; currValueIndex++)
			{
				strCurrentValue.append(",");
				strCurrentValue.append(value.get()[currValueIndex]);

				vecCurrentValues.push_back(value.get()[currValueIndex]);
			}
		}
		
		scoped_smptr<char> valueOld;
		status = AOM_ask_value_string(auditObjectTag, szPropertyNameOld.c_str(), &valueOld);

		vector<string> vecOldValues;
		std::string strValueOld;

		if (valueOld != NULL)
		{
			strValueOld.append(valueOld.getString());
			vecOldValues = il9::utils::String::il9_tokenizeString(strValueOld, ',');	
		}

		logical misMatchFound = false;

		if (vecCurrentValues.size() == vecOldValues.size())
		{
			sort(vecCurrentValues.begin(), vecCurrentValues.end());
			sort(vecOldValues.begin(), vecOldValues.end());

			for (int vecIndex = 0; vecIndex < vecCurrentValues.size(); vecIndex++)
			{
				if (vecCurrentValues[vecIndex].compare(vecOldValues[vecIndex]) != 0)
				{
					misMatchFound = true;
					break;
				}
			}
		}

		if (misMatchFound || (vecCurrentValues.size() != vecOldValues.size()))
		{
			isModified = true;

			propertyInfo.szCurrentValue = any(strCurrentValue);
			propertyInfo.szOldValue = any(strValueOld);
		}
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}

int il9_checkIfPropertyModified(tag_t ObjectTag, il9::utils::AuditLog::ValidatePropertyInput validatePropertyInput, void ***result, int col, int row, bool &isModified,
	il9::utils::AuditLog::PropertyInfo & propertyInfo)
{

	int iFail = ITK_ok;
	ResultStatus status(0);

	////logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try 
	{
		any currentValue;
		any oldValue;

		switch (validatePropertyInput.iType)
		{
			case(POM_string):
			{
				const char* pcOldValue = (char*)result[row][col + 1];

				scoped_smptr<char> spCurrentValue;

				status = AOM_ask_value_string(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &spCurrentValue);

				std::string tempStringValue;
				if (spCurrentValue.get() != NULL) tempStringValue.append(spCurrentValue.getString());

				std::string tempStringValueOld;
				if (pcOldValue != NULL) tempStringValueOld.append(pcOldValue);

				if (tempStringValue.compare(tempStringValueOld) != 0) isModified = true;

				currentValue = any(tempStringValue);
				oldValue = any(tempStringValueOld);

				break;
			}
			case(POM_logical):
			{
				logical lCurrentValue, lOldValue;

				status = AOM_ask_value_logical(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &lCurrentValue);

				if(result[row][col + 1] != NULL) lOldValue = *((logical*)result[row][col + 1]);

				if (lOldValue != lCurrentValue) isModified = true;

				currentValue = any(lCurrentValue);
				oldValue = any(lOldValue);

				break;
			}
			case(POM_int):
			{
				int iCurrentValue, iOldValue;

				status = AOM_ask_value_int(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &iCurrentValue);
				if (result[row][col + 1] != NULL) iOldValue = *((int*)result[row][col + 1]);

				if (iCurrentValue != iOldValue) isModified = true;

				currentValue = any(iCurrentValue);
				oldValue = any(iOldValue);

				break;
			}
			case(POM_date):
			{
				date_t dtCurrentValue = NULLDATE;
				date_t dtOldValue = NULLDATE;

				status = AOM_ask_value_date(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &dtCurrentValue);
				if (result[row][col + 1] != NULL) dtOldValue = *((date_t*)result[row][col + 1]);

				currentValue = any(dtCurrentValue);
				oldValue = any(dtOldValue);

				int answer = 0;
				status = POM_compare_dates(dtCurrentValue, dtOldValue, &answer);
				if (answer != 0) isModified = true;

				break;
			}
			case(POM_external_reference):
			case(POM_typed_reference):
			case(POM_untyped_reference):
			{
				tag_t tCurrentValue = NULLTAG;
				tag_t tOldValue = NULLTAG;

				status = AOM_ask_value_tag(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &tCurrentValue);
				if (result[row][col + 1] != NULL) tOldValue = *((tag_t*)result[row][col + 1]);

				if (tOldValue != tCurrentValue) isModified = true;

				currentValue = any(tCurrentValue);
				oldValue = any(tOldValue);

				break;
			}
			case(POM_double):
			{
				double dCurrentValue, dOldValue;

				status = AOM_ask_value_double(ObjectTag, validatePropertyInput.szPropertyName.c_str(), &dCurrentValue);
				if (result[row][col + 1] != NULL) dOldValue = *((double*)result[row][col + 1]);

				if (dCurrentValue != dOldValue) isModified = true;

				currentValue = any(dCurrentValue);
				oldValue = any(dOldValue);

				break;
			}
			default:
			{
				/* Hope it will not hit this*/
				logger->error("Skipped adding result");
			}
		}

		propertyInfo.szCurrentValue = currentValue;
		propertyInfo.szOldValue = oldValue;
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}


int il9::utils::AuditLog::il9_prepareAndExecuteQuery(tag_t tObjectTag, date_t dtLoggedAfterDate, std::string strEventTypeName,
	std::vector< il9::utils::AuditLog::ValidatePropertyInput > propNamesToValidate, int &nRows, int &nCols, void**** result)
{
	int iFail = ITK_ok;
	ResultStatus status(0);

	//logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.setInput(tObjectTag);
	journalling.setInput(dtLoggedAfterDate);
	journalling.setInput(strEventTypeName);

	for (int indexPropNames = 0; indexPropNames < propNamesToValidate.size(); indexPropNames++)
	{
		journalling.setInput(propNamesToValidate[indexPropNames].szPropertyName);
		journalling.setInput(propNamesToValidate[indexPropNames].szPropertyNameOld);
		journalling.setInput(propNamesToValidate[indexPropNames].iType);
	}

	journalling.journalRoutineCall();

	try
	{
		//input validations
		status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, tObjectTag, "tObjectTag");
		status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, dtLoggedAfterDate, "dtLoggedAfterDate");
		status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, strEventTypeName, "eventTypeName");

		for (int indexPropNames = 0; indexPropNames < propNamesToValidate.size(); indexPropNames++)
		{
			status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, propNamesToValidate[indexPropNames].szPropertyName, "szPropertyName");
			status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, propNamesToValidate[indexPropNames].szPropertyNameOld, "szPropertyNameOld");
			status = il9::validation::il9_validateInputArgument(logger, __FILE__, __LINE__, propNamesToValidate[indexPropNames].iType, "iType");
		}

		//define SimplePOMEnquiry
		Teamcenter::scoped_ptr<IL9SimplePOMEnquiry> modifyEventAuditLogsQuery;
		modifyEventAuditLogsQuery = new IL9SimplePOMEnquiry("ModifyEventAuditLogsQuery", false);

		//set puid column as a first select attribute, rest of the attributes are added to the query as property names are processed
		vector <string> vectorSelectAttrs;
		vectorSelectAttrs.push_back(ATTR_PUID);

		for (int indexPropNames = 0; indexPropNames < propNamesToValidate.size(); indexPropNames++)
		{
			if (propNamesToValidate[indexPropNames].iType != POM_long_string)
			{
				//Set select attributes for property names
				vectorSelectAttrs.push_back(propNamesToValidate[indexPropNames].szPropertyName);
				vectorSelectAttrs.push_back(propNamesToValidate[indexPropNames].szPropertyNameOld);
			}
		}

		vector < std::pair<const std::string, vector <string> > > finalVectorOfselectAttrs;
		finalVectorOfselectAttrs.push_back({ IL9_TYPE_FND0GENERALAUDIT, vectorSelectAttrs });
		status = modifyEventAuditLogsQuery->addSelectAttributes(finalVectorOfselectAttrs);

		vectorSelectAttrs.clear();
		finalVectorOfselectAttrs.clear();

		//bind values to the properties
		modifyEventAuditLogsQuery->addValue(IL9_TYPE_FND0GENERALAUDIT, OBJECT_TAG, POM_enquiry_equal, POM_external_reference, { any(tObjectTag) });
		modifyEventAuditLogsQuery->addValue(IL9_TYPE_FND0GENERALAUDIT, EVENT_TYPE_NAME, POM_enquiry_equal, POM_string, { any(strEventTypeName) });
		modifyEventAuditLogsQuery->addValue(IL9_TYPE_FND0GENERALAUDIT, LOGGED_DATE, POM_enquiry_greater_than_or_eq, POM_date, { any(dtLoggedAfterDate) });

		//set sorting order
		//POM Enquiry adds extra column to the result for LOGGED_DATE attribute iternally since the column is added in ORDER BY clause
		status = modifyEventAuditLogsQuery->orderBy(IL9_TYPE_FND0GENERALAUDIT, LOGGED_DATE, POM_enquiry_desc_order);

		//Sample Query
		//SELECT  DISTINCT t_01.puid, t_01.pil9_stocking_type, t_01.pil9_stocking_typeOvl, t_01.pil9_batch_class, 
		//t_01.pil9_batch_classOvl, t_01.pil9_serialization, t_01.pil9_serializationOvl, t_01.pil9_is_batch_management, t_01.pil9_is_batch_managementOvl, 
		//t_01.pil9_camstar_integration, t_01.pil9_camstar_integrationOvl, t_01.pil9_last_review_date, t_01.pil9_last_review_dateOvl, 
		//t_01.pil9_shelf_life_duration, t_01.pil9_shelf_life_durationOvl, t_01.pfnd0LoggedDate FROM PFND0GENERALAUDIT t_01 WHERE
		//(((t_01.pfnd0Object = 'I6U1smQOvgWMLAAAAAAAAAAAAAA') AND(t_01.pfnd0EventTypeName = '__Modify')) 
		//AND((t_01.pfnd0LoggedDate >= CONVERT(datetime, '2020-12-24 01:33:00', 120)) 
		//)) ORDER BY t_01.pfnd0LoggedDate DESC;
		
		
		//run query
		logger->debug("\n Running Query --> ");
		status = modifyEventAuditLogsQuery->run(&nRows, &nCols, result);
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}

int il9::utils::AuditLog::il9_trackPropertyValueChange(tag_t tObjectTag, date_t dtLoggedAfterDate, std::string eventTypeName, il9::utils::AuditLog::ValidatePropertyInput  propertyInputToValidate,
	std::vector < il9::utils::AuditLog::ModifiedPropertyInfo > &vectorModifiedPropertyInfo)
{
	int iFail = ITK_ok;
	ResultStatus status(0);

	////logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try
	{
		int nRows = 0;
		int nCols = 0;
		void*** result = NULL;

		//prepare and execute query
		vector<il9::utils::AuditLog::ValidatePropertyInput> tempVectPropNamesToVal;
		tempVectPropNamesToVal.push_back(il9::utils::AuditLog::ValidatePropertyInput());

		tempVectPropNamesToVal[0].iType = propertyInputToValidate.iType;
		tempVectPropNamesToVal[0].szPropertyName = propertyInputToValidate.szPropertyName;
		tempVectPropNamesToVal[0].szPropertyNameOld = propertyInputToValidate.szPropertyNameOld;

		status = il9_prepareAndExecuteQuery(tObjectTag, dtLoggedAfterDate, eventTypeName, tempVectPropNamesToVal,
			nRows, nCols, &result);

		logger->debug("\n Output --> ");

		if (nRows > 0 && nCols > 1)
		{
			// add audit object tag to the output vector
			tag_t auditObjectTag = NULLTAG;

			auditObjectTag = *((tag_t *)result[nRows - 1][0]);
			logger->debug("\n   -> " + getPUID(auditObjectTag));

			any tempCurrentValue;
			any tempOldValue;

			bool isModified = false;

			int col_index = 1;

			il9::utils::AuditLog::PropertyInfo tempPropertyInfo;

			if (propertyInputToValidate.iType == POM_long_string)
			{
				status = il9_checkIfLongStringPropertyModified(tObjectTag, auditObjectTag, propertyInputToValidate.szPropertyName,
					propertyInputToValidate.szPropertyNameOld, isModified, tempPropertyInfo);
			}
			else
			{
				status = il9_checkIfPropertyModified(tObjectTag, propertyInputToValidate, result, col_index, nRows - 1, isModified,
					tempPropertyInfo);
			}

			//add property info to temp vector
			if (isModified)
			{
				//add temp property info vector to output vector
				vectorModifiedPropertyInfo.push_back(il9::utils::AuditLog::ModifiedPropertyInfo());

				vectorModifiedPropertyInfo[0].objectTag = auditObjectTag;
				vectorModifiedPropertyInfo[0].propertyInfo = { propertyInputToValidate.szPropertyName , 
					tempPropertyInfo.szCurrentValue, tempPropertyInfo.szOldValue  };
			}

			//clean up
			MEM_free(result);
		}
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		//logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}

int il9::utils::AuditLog::il9_getModifiedPropertiesInfo(tag_t tObjectTag, date_t dtLoggedAfterDate, std::string strEventTypeName, std::vector< il9::utils::AuditLog::ValidatePropertyInput > propNamesToValidate,
	int &numOfModifiedProperties, std::vector< il9::utils::AuditLog::PropertyInfo > &modifiedProperties)
{
	int iFail = ITK_ok;
	ResultStatus status(0);

	//logger
	Teamcenter::Logging::Logger *logger = Teamcenter::Logging::Logger::getLogger("Teamcenter.IL9.IL9common.il9.utils.AuditLog");
	IL9_LogEntryExit logEntryExit(logger, __func__);

	//journalling
	il9::IL9_JournalLog journalling(__func__, &iFail);
	journalling.journalRoutineCall();

	try
	{
		int nRows = 0;
		int nCols = 0;
		void*** result = NULL;

		//prepare and execute query
		status = il9_prepareAndExecuteQuery(tObjectTag, dtLoggedAfterDate, strEventTypeName, propNamesToValidate,
			nRows, nCols, &result);

		//evaluate modified properties
		std::unordered_set<std::string> hsModifiedPropertyNames;//hashset to keep track of property info structs that are already added to the return value

		logger->debug("\n Output --> ");

		if (nRows > 0 && nCols > 1)
		{
			tag_t auditObjectTag = *((tag_t *)result[nRows - 1][0]);
			logger->debug("\n   -> " + getPUID(auditObjectTag));

			il9_validateNonLongStringPropertyValues(tObjectTag, nRows - 1, nCols, propNamesToValidate, result, numOfModifiedProperties, hsModifiedPropertyNames, modifiedProperties);
			il9_validateLongStringPropertyValues(tObjectTag, auditObjectTag, propNamesToValidate, numOfModifiedProperties, hsModifiedPropertyNames, modifiedProperties);

			//clean up
			MEM_free(result);
			hsModifiedPropertyNames.clear();

			//journalling
			journalling.setOutput("numOfModifiedProperties", numOfModifiedProperties);
			journalling.journalRoutineCall();
		}
	}
	catch (IFail &exception)
	{
		iFail = exception.ifail();
		logger->error(__FILE__, __LINE__, exception.ifail(), exception.getMessage());
	}

	return iFail;
}