        $chron = gwmi -Class win32_product | where name -like "*chronicall*"
        $forti = gwmi -Class win32_product | where name -like "*fort*"
        if ($forti){ C:\temp\bootstrap_files\forti.exe}
        if ($chron){ C:\temp\bootstrap_files\Chronicall_4_2_10e.exe}
