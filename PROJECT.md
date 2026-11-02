# Cyber Security Awareness Platform — Project Summary

## 1. Project goal

The **Cyber Security Awareness Platform** is a machine-learning-based application intended to help users identify potentially dangerous digital content, particularly:

* Phishing websites and URLs.
* Smishing messages and suspicious SMS content.
* Digital arrest and other scam-related messages.
* Malicious Android applications.

The intended experience is to let users submit suspicious content and receive a risk assessment.

The project is designed around actual ML classification models rather than a collection of manually written detection rules. The aim is to build a system that can classify suspicious content and eventually provide useful, understandable results to users.

**Important scope distinction:** The project has research and implementation progress across web phishing, SMS/smishing, and Android classification. However, these capabilities are at different stages of maturity. They are not all integrated into the application yet.

---

## 2. Architecture

### Technology stack

| Layer               | Technology            | Responsibility                                  |
| ------------------- | --------------------- | ----------------------------------------------- |
| Frontend            | React + Vite          | User interface and input collection             |
| Backend             | Python + FastAPI      | API endpoints and model inference               |
| ML                  | scikit-learn          | Feature extraction, training and classification |
| Model serialization | Joblib                | Saving and loading trained models               |
| Data processing     | Python, pandas, NumPy | Dataset preparation and analysis                |
| Evaluation          | scikit-learn metrics  | Model comparison and validation                 |

### High-level architecture

```text
                 User
                  |
                  v
          React + Vite Frontend
                  |
                  v
             FastAPI Backend
                  |
        -----------------------
        |          |          |
        v          v          v
   Web/Text     SMS Model   Android Model
   Classifier   (planned)   Classifier
        |          |          |
        -----------------------
                  |
                  v
          Prediction Result
                  |
                  v
           Frontend Display
```

The backend loads model artifacts during FastAPI startup. Models are not trained when users submit requests; the API performs inference using already-trained models.

### Existing API endpoints

| Endpoint                       | Purpose                        | Current capability                                   |
| ------------------------------ | ------------------------------ | ---------------------------------------------------- |
| `POST /api/ml/analyze`         | Text/web phishing analysis     | Uses the existing V2 text model                      |
| `POST /api/ml/analyze-android` | Android feature classification | Accepts a prepared vector of 226 configured features |

The Android endpoint does **not** accept an APK and automatically inspect it. It currently expects the feature values to be extracted and supplied beforehand.

---

## 3. What has been completed

The project has progressed through several research and implementation stages.

### A. Application foundation

The following foundation has been established:

* React + Vite frontend.
* FastAPI backend.
* ML inference endpoints.
* Model loading at backend startup.
* Separate model artifacts and experiment reports.
* An ML-only architecture; the earlier rule-based analyzer was removed.

The existing application has a working integration path for the V2 text classifier and Android prepared-feature classifier.

### B. Web phishing detection — V2

A text phishing classifier was trained using:

* Word-level TF-IDF features.
* Unigrams and bigrams.
* Logistic Regression.
* Domain-held-out evaluation to reduce leakage between training and validation data.

Its main reported performance was:

| Metric    | V2 test result |
| --------- | -------------: |
| Accuracy  |          89.5% |
| Precision |         90.93% |
| Recall    |         88.11% |
| F1-score  |         89.50% |
| ROC-AUC   |         0.9113 |

The model works reasonably well on its original evaluation distribution, but its performance on long HTML content is a significant weakness.

### C. Web phishing detection — V3 experiments

V3 introduced a dual-channel architecture.

It uses two types of information:

**Content channel:** Extracts visible text from HTML, including page titles and anchor text.

**URL channel:** Extracts information about hosts, domains, subdomains, paths and query parameter names.

Three model variants were developed:

1. Content-only model.
2. URL-only model.
3. Dual-channel model.

A hybrid routing approach was also investigated, using V3 for selected HTML inputs and V2 for other text inputs.

The main finding was that V3 improved classification of long HTML phishing content compared with V2 on the original validation experiments.

However, the independent CompPhish evaluation showed that the models are not production-ready. At the 0.50 threshold:

| Model       | Precision | Recall | F1-score | Specificity |
| ----------- | --------: | -----: | -------: | ----------: |
| V2          |    77.57% |  8.85% |   15.89% |      97.74% |
| V3 URL-only |    68.65% | 88.49% |   77.32% |      64.31% |
| V3 Dual     |    71.22% | 67.80% |   69.47% |      75.80% |

This evaluation exposed a major generalization problem: performance on the original data did not translate reliably to the independent HTML dataset.

### D. SMS and smishing research

The project explored multiple datasets and developed a dedicated SMS classification track.

The work included:

* Recovering original labels from the Mishra & Soni dataset.
* Examining UCI SMS Spam Collection.
* Exploring ExAIS.
* Studying the WSPR-NCSU SMS phishing dataset.
* Investigating the Smishing-Dataset-IMC25 dataset.
* Performing exact and near-duplicate screening.
* Designing source-aware, leakage-controlled dataset splits.

#### SMS-03

Three model variants were developed:

* Word TF-IDF + Logistic Regression.
* Character TF-IDF + Logistic Regression.
* Combined word and character TF-IDF model.

SMS-03 achieved strong internal test results:

| Metric      | Internal test |
| ----------- | ------------: |
| Accuracy    |        98.26% |
| Precision   |        96.67% |
| Recall      |        96.67% |
| Specificity |        98.83% |
| F1-score    |        96.67% |
| ROC-AUC     |        0.9972 |

However, a held-out Mishra & Soni evaluation exposed a serious limitation.

Its recall on linkless smishing messages was only **0.64%**. It performed substantially better on URL-bearing smishing messages.

The model therefore learned a strong association with URL-related patterns and failed to generalize to many linkless scam messages.

This was an important finding: high internal test performance does not necessarily indicate real-world generalization.

### E. SMS-05 dataset preparation

SMS-05 is the next major model-development stage.

A new dataset was assembled using three target categories:

* Smishing.
* Ham.
* Commercial spam.

The current dataset manifest contains:

| Category        |   Records |
| --------------- | --------: |
| Smishing        |     3,400 |
| Ham             |     3,500 |
| Commercial spam |     1,835 |
| **Total**       | **8,735** |

The positive smishing class is balanced by message type:

| Smishing type | Records |
| ------------- | ------: |
| URL-bearing   |   1,700 |
| Linkless      |   1,700 |

The dataset has been divided into training, validation and internal test sets. Exact-hash and connected-component leakage across those partitions was reported as zero.

Four model candidates have been specified:

| Model    | Approach                                                 |
| -------- | -------------------------------------------------------- |
| SMS-05-A | Word-level TF-IDF + Logistic Regression                  |
| SMS-05-B | Character-level TF-IDF + Logistic Regression             |
| SMS-05-C | Combined word and character TF-IDF                       |
| SMS-05-D | URL-excluded content features + structured text features |

The training workflow has been planned, but **SMS-05 training and final model selection have not yet been completed**.

### F. Android malicious application detection

An Android classification pipeline has been prepared around a 226-feature input representation.

The backend can accept the prepared feature vector and classify it.

However, the actual APK-to-feature extraction pipeline has not been established. This means users cannot currently upload an APK and receive a fully automated malware assessment.

---

## 4. What is left

The remaining work falls into five major areas.

### Priority 1 — Complete SMS-05

This is the immediate next research task.

Before training:

1. Reconcile the remaining IMC25 dataset accounting discrepancies.
2. Verify the final dataset manifest and category counts.
3. Verify source-level and split-level distributions.
4. Confirm that metadata is not being used as a predictive feature.

Then:

1. Train SMS-05-A, B, C and D.
2. Compare the candidates using validation data.
3. Select the best model according to the predefined evaluation criteria.
4. Freeze the selected model.
5. Evaluate it once on the internal test set.
6. Produce a detailed report covering URL-bearing and linkless smishing separately.

The 500-message Mishra & Soni benchmark must remain quarantined because its results already influenced SMS-05 model design.

### Priority 2 — Improve web phishing detection

V3 needs further evaluation before deployment.

Remaining work includes:

* Investigating the high false-positive rate on CompPhish.
* Performing stronger duplicate-aware analysis.
* Testing on a fresh, representative dataset.
* Evaluating URL-only and dual-channel models under realistic class prevalence.
* Selecting an appropriate threshold using validation data.
* Deciding whether V2, V3 or a hybrid model should be deployed.

The current evidence does not justify replacing V2 with V3 in production.

### Priority 3 — Android feature extraction

The missing component is the connection between an APK and the 226 model features.

This requires:

* Selecting or implementing an APK analysis and feature extraction method.
* Establishing a reliable mapping from APK properties to the model's expected feature names.
* Validating the extracted feature representation.
* Testing the complete APK-to-classification pipeline.

Until this exists, Android detection should be described as prepared-feature classification, not automatic APK scanning.

### Priority 4 — Integrate selected models into the application

Once suitable models are validated:

* Add the selected SMS model to FastAPI.
* Integrate the relevant V3 model only if its evaluation supports deployment.
* Update the frontend to support each input type.
* Standardize model responses.
* Add appropriate validation and error handling.
* Test the complete frontend-to-backend inference flow.

At the last known integration audit, V3 and SMS-03 were not active in FastAPI. SMS-05 has not yet been trained or integrated.

### Priority 5 — Testing and deployment

The final application will need:

* Backend unit and integration tests.
* Frontend testing.
* Input validation and payload limits.
* Model versioning and artifact integrity checks.
* Performance testing.
* Deployment configuration.
* Documentation explaining model limitations and appropriate use.

---

## 5. Important decisions made

These decisions should guide future development.

| Area                   | Decision                                                                                        |
| ---------------------- | ----------------------------------------------------------------------------------------------- |
| Overall approach       | ML-based detection; do not reintroduce the removed rule-based analyzer.                         |
| Frontend               | React + Vite.                                                                                   |
| Backend                | Python + FastAPI.                                                                               |
| Model training         | Train offline; load frozen artifacts during API startup.                                        |
| Web phishing           | Keep V2 as the existing integrated baseline while evaluating V3.                                |
| V3 architecture        | Investigate separate content and URL channels rather than relying only on text TF-IDF.          |
| SMS classification     | Develop a dedicated SMS model instead of reusing the existing web phishing classifier.          |
| SMS-05 model selection | Compare word, character, combined and structured-feature approaches.                            |
| Dataset handling       | Preserve original labels and perform record-level duplicate screening.                          |
| Data splitting         | Use connected-component grouping to prevent exact and detected near-duplicate leakage.          |
| Evaluation             | Use validation data for model selection and reserve the internal test set for final evaluation. |
| Android                | Treat the current model as a prepared-feature classifier until APK extraction is implemented.   |
| Production readiness   | Do not deploy a model solely because it has strong internal test metrics.                       |

---

## 6. Known issues and limitations

These are the most important issues to keep visible.

### Web phishing

* V2 struggles with long HTML inputs.
* V3 URL-only has high recall on CompPhish but also a high false-positive rate.
* V3 Dual has a better specificity trade-off but misses a considerable number of phishing samples.
* Hybrid policies do not provide a meaningful advantage on an evaluation set containing only HTML inputs.
* The CompPhish evaluation contains significant duplicate and near-duplicate structure. Exact-group-weighted results were lower than ordinary record-level results, and the full near-duplicate graph could not be reconstructed.
* Real-world phishing prevalence is much lower than the balanced or stratified research datasets. This can make production precision substantially worse.

### SMS

* SMS-03 performs poorly on linkless smishing despite excellent internal metrics.
* SMS-05 still has source-label confounding: some datasets contribute mostly or exclusively positives, while others contribute mostly or exclusively negatives.
* WSPR positives are URL-bearing by construction.
* IMC positives contribute most of the linkless positive examples.
* ExAIS participants overlap across dataset splits, so the evaluation does not establish generalization to completely unseen users.
* UCI commercial spam samples are limited, making strong conclusions about that source difficult.

### SMS-05 dataset accounting

Three unresolved accounting discrepancies must be checked before training:

1. The reported counts of actual SMS, OCR stubs, warning posts and excluded records do not fully account for all 22,078 English records.
2. The IMC25 taxonomy reports 1,384 spam-category records, while 1,173 unique spam-tagged records were reported as quarantined.
3. Earlier and later smishing candidate counts do not reconcile exactly after accounting for quarantined records.

These may be reporting or filtering inconsistencies, but they should not be silently corrected. The underlying row-level manifest must establish the correct figures.

### Android

* No verified APK-to-feature extraction pipeline is available.
* The endpoint requires 226 prepared feature values.
* Dataset exploration has not yet established a sufficiently reliable end-to-end APK analysis workflow.

### Project scope

The platform's original goal includes digital arrest scams. However, the current work does not establish a separately trained and validated digital-arrest-specific classifier. The SMS track is primarily focused on smishing classification. Digital-arrest-specific coverage still needs to be demonstrated.

---

## 7. Current project status

| Component                          | Status                                                              |
| ---------------------------------- | ------------------------------------------------------------------- |
| React + Vite frontend              | Foundation established                                              |
| FastAPI backend                    | Foundation established                                              |
| Web phishing V2                    | Trained, evaluated and integrated                                   |
| Web phishing V3                    | Trained and evaluated experimentally; not integrated                |
| SMS-03                             | Trained and evaluated; poor linkless generalization; not integrated |
| SMS-05 dataset                     | Prepared; accounting reconciliation outstanding                     |
| SMS-05 models                      | Training and selection pending                                      |
| Android classifier                 | Prepared-feature endpoint available                                 |
| APK feature extraction             | Not implemented                                                     |
| Digital-arrest-specific classifier | Not established                                                     |
| Final deployment                   | Pending                                                             |

## 8. Recommended next step

The immediate priority should be **SMS-05 dataset preflight and model training**, not frontend modifications or API integration.

The development sequence should be:

```text
Reconcile SMS-05 dataset
          |
          v
Verify dataset and split manifests
          |
          v
Train SMS-05-A / B / C / D
          |
          v
Compare validation performance
          |
          v
Select and freeze winning model
          |
          v
Evaluate internal test once
          |
          v
Document limitations and generalization
          |
          v
Integrate validated model into FastAPI
          |
          v
Connect frontend and test end-to-end
```

**Overall assessment:** The project has moved beyond a basic awareness-website prototype. It now has a functioning application foundation and substantial ML experimentation across web phishing, SMS and Android detection. The biggest remaining challenge is not simply building more models; it is demonstrating that the selected models generalize to genuinely unseen, realistic scam messages and websites before integrating them into the application.
