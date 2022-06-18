# Contributing

## Creating a new project based on this one

You can create a new project by cloning this repo and running the rename project script.
That will rename the project to a new name and update the references to that project.

So running:

```sh
git clone --depth=1 https://github.com/oneconcern/geodude new-project-name
cd new-project-name
EMAIL=you@oneconcern.com ./hack/rename-project
```

