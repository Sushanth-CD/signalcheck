# Android APK feature extraction readiness

## Decision

Do not add `POST /api/ml/analyze-apk` or an APK upload control yet. The current
model requires a positional vector of 226 binary features, but the reviewed
training artifacts do not define a reliable APK-manifest extraction mapping
for all 226 values. Returning a prediction now would require guessing or
substituting values, which could make a valid-shaped input misleading.

No model, dataset, endpoint, dependency, or frontend code was changed for APK
extraction.

## Verified model input

- The authoritative ordered list is `feature_columns` in
  `backend/reports/ml/android_malware_sklearn_1_8_0/experiment_config.json`.
- The configuration and saved input-schema audit identify 226 binary values.
- The compatibility notebook builds model matrices from the processed
  candidate table with `to_numpy(dtype=np.uint8)` and fits the pipeline on
  that ordered matrix. It does not derive the inputs by parsing APK files.
- The feature set includes human-readable permission descriptions and
  permission-name strings, but the reviewed artifacts do not specify a
  complete, versioned mapping from Android manifest permission names to those
  dataset columns.

## Unresolved feature semantics

The final 19 feature names in model order are not ordinary declared Android
permission names. Their meaning and extraction source are not defined in the
saved model configuration or the inspected training notebook:

```json
[
  " SMS_MMS__SMS_MMS ",
  " SMS_MMS__FILE ",
  " SMS_MMS__DATABASE_INFORMATION ",
  " FILE_INFORMATION__FILE_INFORMATION ",
  " FILE_INFORMATION__BROWSER_INFORMATION ",
  " FILE_INFORMATION__AUDIO ",
  " FILE__DATABASE_INFORMATION ",
  " BLUETOOTH__BUNDLE ",
  " BLUETOOTH_INFORMATION__VOIP ",
  " BLUETOOTH_INFORMATION__DATABASE_INFORMATION ",
  " BLUETOOTH_INFORMATION__IPC ",
  " BLUETOOTH_INFORMATION__CONTACT_INFORMATION ",
  " VOIP__VIDEO ",
  " NETWORK__VOIP ",
  " BROWSER_INFORMATION__ACCOUNT_INFORMATION ",
  " IPC__NFC ",
  " SYNCHRONIZATION_DATA__BUNDLE ",
  " ACTION_MAIN ",
  " ACTION_BATTERY_OKAY "
]
```

The two `ACTION_*` names resemble Android intent action values, but the
training artifacts do not establish that simple presence in a manifest is
the exact label-generation rule. The other 17 grouped names have no
documented manifest mapping. These values cannot safely be replaced with
zero when the parser cannot determine them.

Likewise, the description-style permission columns need a documented mapping
from manifest permission identifiers to the source dataset's exact feature
semantics. Similar wording is not sufficient evidence of equivalent values.

## Parser and environment check

No Androguard, APK, or Android binary-manifest parser package was found in the
existing `backend/.venv-ml/Lib/site-packages` directory. No dependency was
installed. The environment's Python launcher points to Python 3.14.6 under
the user profile, and Windows returned `Access is denied` when that
interpreter was invoked. Parser compatibility and its documented API could
therefore not be verified or tested in the active environment.

The existing prepared-feature endpoint `POST /api/ml/analyze-android`
remains the supported Android inference path. It accepts the exact 226-name
map and uses the already-loaded Random Forest model. It does not inspect APKs.

## Requirements before implementation

1. Obtain authoritative documentation or source code for how all 226
   workbook features were generated, including the 17 grouped features and
   the `ACTION_*` values.
2. Define and review an explicit APK-to-feature mapping, including Android
   permission aliases, custom permissions, SDK/version behavior, and unknown
   or unextractable values. Any unknown value must fail analysis rather than
   become zero.
3. In an accessible Python 3.14.6 / scikit-learn 1.8.0 environment, select a
   compatible static parser and verify its documented binary manifest API.
4. Add fixture-based extraction tests and compare parser-derived features
   with authoritative feature vectors before enabling prediction.
5. Only after those checks pass, add the upload endpoint and separate UI
   workflow. Until then, do not describe APK upload or automatic extraction
   as supported.
